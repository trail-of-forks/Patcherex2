from __future__ import annotations

import io
import logging
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from subprocess import CalledProcessError
from typing import TYPE_CHECKING, Any, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import cle
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import (
    ENUM_RELOC_TYPE_AARCH64,
    ENUM_RELOC_TYPE_ARM,
    ENUM_RELOC_TYPE_MIPS,
    ENUM_RELOC_TYPE_PPC,
    ENUM_RELOC_TYPE_PPC64,
    ENUM_RELOC_TYPE_S390X,
    ENUM_RELOC_TYPE_i386,
    ENUM_RELOC_TYPE_x64,
)
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.compilers import (
    CompilationEngine,
    CompilerPipeline,
    ObjectCompiler,
)

if TYPE_CHECKING:
    from patcherex2.components.arch import ArchitectureInfo
    from patcherex2.components.symbol_resolver import SymbolResolver

logger = logging.getLogger(__name__)

LINKER_SCRIPT_NAME_RE = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$]*$")
LOCATION_COUNTER = "."
_ELF_RELOCATION_TYPE_MAP: Mapping[str, Mapping[str, int]] = {
    "EM_X86_64": ENUM_RELOC_TYPE_x64,
    "EM_386": ENUM_RELOC_TYPE_i386,
    "EM_AARCH64": ENUM_RELOC_TYPE_AARCH64,
    "EM_ARM": ENUM_RELOC_TYPE_ARM,
    "EM_MIPS": ENUM_RELOC_TYPE_MIPS,
    "EM_PPC": ENUM_RELOC_TYPE_PPC,
    "EM_PPC64": ENUM_RELOC_TYPE_PPC64,
    "EM_S390": ENUM_RELOC_TYPE_S390X,
}


class ObjectArchMismatchError(RuntimeError):
    """Raised when compiled object code targets the wrong architecture."""


class UndefinedSymbolError(RuntimeError):
    """Raised when a linked patch object still references an undefined symbol."""


class UnsupportedRelocationError(RuntimeError):
    """Raised when a patch uses a relocation incompatible with its target."""


def create_elf_compiler(
    architecture: ArchitectureInfo,
    symbol_resolver: SymbolResolver,
    object_compiler: ObjectCompiler,
    linker: str,
    position_independent: bool,
    *,
    resolve_address_symbols: bool = False,
    command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
) -> CompilerPipeline:
    """Compose an object compiler with an ELF compilation engine."""
    engine = ElfCompilationEngine(
        architecture=architecture,
        symbol_resolver=symbol_resolver,
        linker=linker,
        position_independent=position_independent,
        resolve_address_symbols=resolve_address_symbols,
        command_runner=command_runner,
    )
    return CompilerPipeline(object_compiler, engine)


@final
class ElfCompilationEngine(CompilationEngine):
    """Resolve, link, validate, and extract code from ELF objects."""

    def __init__(
        self,
        architecture: ArchitectureInfo,
        symbol_resolver: SymbolResolver,
        linker: str,
        position_independent: bool,
        *,
        resolve_address_symbols: bool = False,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.architecture: ArchitectureInfo = architecture
        self.symbol_resolver: SymbolResolver = symbol_resolver
        self.linker: str = linker
        self.position_independent: bool = position_independent
        self.resolve_address_symbols: bool = resolve_address_symbols
        self.command_runner = command_runner

    @override
    def compile(
        self,
        object_bytes: bytes,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
    ) -> bytes:
        """Resolve and link a relocatable ELF object into patch bytes."""
        resolved_symbols = self.symbol_resolver.resolve(symbols)
        with io.BytesIO(object_bytes) as stream:
            elf = ELFFile(stream)
            self.check_got_relocations(elf, set(resolved_symbols))
            self.check_object_arch(elf)
            rodata_sections = self._linker_rodata_sections(elf)
            if self.resolve_address_symbols:
                self._add_address_symbols(elf, resolved_symbols)
        linker_symbols = self.linker_script_symbols(resolved_symbols)
        return self._link_object(object_bytes, base, linker_symbols, rodata_sections)

    @staticmethod
    def linker_script_symbols(symbols: Mapping[str, int]) -> dict[str, int]:
        """Return symbols whose names are valid in a linker script."""
        usable, dropped = {}, []
        for name, address in symbols.items():
            if name != LOCATION_COUNTER and LINKER_SCRIPT_NAME_RE.match(name):
                usable[name] = address
            else:
                dropped.append(name)
        if dropped:
            logger.debug(
                "omitted %d linker-script symbol(s) with invalid names: %s",
                len(dropped),
                ", ".join(sorted(dropped)[:5]),
            )
        return usable

    @staticmethod
    def _linker_rodata_sections(elf: ELFFile) -> str:
        return " ".join(
            f". = ALIGN({section['sh_addralign']}); *({section.name})"
            for section in elf.iter_sections()
            if section.name.startswith(".rodata")
        )

    @staticmethod
    def _add_address_symbols(elf: ELFFile, symbols: dict[str, int]) -> None:
        symbol_table = elf.get_section_by_name(".symtab")
        if not isinstance(symbol_table, SymbolTableSection):
            raise RuntimeError(  # noqa: TRY004 - the ELF is malformed, not an argument type.
                "Recompiled object has no symbol table"
            )
        for symbol in symbol_table.iter_symbols():
            if symbol.entry.st_shndx != "SHN_UNDEF" or "_" not in symbol.name:
                continue
            try:
                _, address = symbol.name.split("_", 1)
                symbols.setdefault(symbol.name, int(address, 16))
            except ValueError:
                continue

    def check_object_arch(self, elf: ELFFile) -> None:
        """Reject an ELF object that does not match the target architecture."""
        expected = self.architecture.elf_arch
        actual = {
            "e_machine": elf.header["e_machine"],
            "ei_class": elf.header["e_ident"]["EI_CLASS"],
            "ei_data": elf.header["e_ident"]["EI_DATA"],
        }
        mismatched = {
            key: (value, actual[key]) for key, value in expected.items() if actual[key] != value
        }
        if not mismatched:
            return
        details = ", ".join(
            f"{key}: expected {want}, got {got}" for key, (want, got) in mismatched.items()
        )
        raise ObjectArchMismatchError(
            f"Compiled patch code does not match the target architecture ({details})"
        )

    @staticmethod
    def check_undefined_symbols(elf: ELFFile) -> None:
        """Reject a linked object that still references undefined symbols."""
        symbol_table = elf.get_section_by_name(".symtab")
        if not isinstance(symbol_table, SymbolTableSection):
            return
        undefined = {
            index: symbol.name
            for index, symbol in enumerate(symbol_table.iter_symbols())
            if symbol.name and symbol.entry.st_shndx == "SHN_UNDEF"
        }
        unresolved = set()
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            linked_symbols = elf.get_section(section["sh_link"])
            if (
                not isinstance(linked_symbols, SymbolTableSection)
                or linked_symbols.name != symbol_table.name
            ):
                continue
            for relocation in section.iter_relocations():
                name = undefined.get(relocation.entry.r_info_sym)
                if name is not None:
                    unresolved.add(name)
        if unresolved:
            raise UndefinedSymbolError(
                "Linked patch object references undefined symbols: " + ", ".join(sorted(unresolved))
            )

    def check_got_relocations(self, elf: ELFFile, defined_symbols: set[str]) -> None:
        """Reject fixed-address relocations that require a GOT."""
        e_machine: str = elf.header["e_machine"]
        if (relocation_types := _ELF_RELOCATION_TYPE_MAP.get(e_machine)) is None:
            raise UnsupportedRelocationError(f"Missing relocation types for {e_machine}")
        relocation_names = {value: name for name, value in relocation_types.items()}
        invalid = set()
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbol_table = elf.get_section(section["sh_link"])
            if not isinstance(symbol_table, SymbolTableSection):
                continue
            for relocation in section.iter_relocations():
                symbol = symbol_table.get_symbol(relocation.entry.r_info_sym)
                if symbol.name not in defined_symbols:
                    continue
                relocation_name = relocation_names.get(
                    relocation.entry.r_info_type,
                    f"type {relocation.entry.r_info_type}",
                )
                if self._relocation_needs_got(elf, section, relocation, relocation_name):
                    invalid.add((symbol.name, relocation_name, section.name))
        if invalid:
            details = ", ".join(
                f"{name} ({relocation} in {section})"
                for name, relocation, section in sorted(invalid)
            )
            raise UnsupportedRelocationError(
                f"Fixed-address patch references absolute symbols through unsupported relocations: {details}"
            )

    @staticmethod
    def _relocation_needs_got(
        elf: ELFFile,
        section: RelocationSection,
        relocation: Any,
        name: str,
    ) -> bool:
        return (
            "GOT" in name
            or (elf.header["e_machine"] == "EM_386" and relocation.entry.r_info_type == 43)
            or (elf.header["e_machine"] == "EM_PPC64" and section.name.endswith(".toc"))
        )

    def _link_object(
        self,
        object_bytes: bytes,
        base: int,
        symbols: Mapping[str, int],
        rodata_sections: str,
    ) -> bytes:
        symbol_definitions = "".join(
            f"{name} = {hex(address)};" for name, address in symbols.items()
        )
        script = (
            "SECTIONS { .patcherex2 : SUBALIGN(0) { "
            f". = {hex(base)}; *(.text) {rodata_sections} {symbol_definitions} }} }}"
        )
        with tempfile.TemporaryDirectory() as directory:
            object_path = os.path.join(directory, "obj.o")
            script_path = os.path.join(directory, "linker.ld")
            linked_path = os.path.join(directory, "obj_linked.o")
            with open(object_path, "wb") as stream:
                stream.write(object_bytes)
            with open(script_path, "w") as stream:
                stream.write(script)
            self._run_linker(object_path, script_path, linked_path)
            with open(linked_path, "rb") as stream:
                self.check_undefined_symbols(ELFFile(stream))
            return self._extract_code(linked_path, base)

    def _run_linker(self, object_path: str, script_path: str, linked_path: str) -> None:
        try:
            self.command_runner.run(
                [
                    self.linker,
                    "-relocatable",
                    object_path,
                    "-T",
                    script_path,
                    "-o",
                    linked_path,
                ]
            )
        except CalledProcessError as error:
            logger.error(error.stderr.decode("utf-8"))
            raise

    @staticmethod
    def _extract_code(linked_path: str, base: int) -> bytes:
        loader = cle.Loader(linked_path, main_opts={"base_addr": 0x0})
        section = next(
            (section for section in loader.main_object.sections if section.name == ".patcherex2"),
            None,
        )
        if section is None:
            raise RuntimeError("Linked patch object has no .patcherex2 section")
        compiled_start = loader.all_objects[0].entry + base
        return loader.memory.load(
            compiled_start,
            section.memsize - compiled_start,
        )
