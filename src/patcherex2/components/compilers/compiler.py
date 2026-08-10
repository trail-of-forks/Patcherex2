from __future__ import annotations

import io
import logging
import os
import re
import subprocess
import tempfile

import cle
from elftools.elf import enums
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)

#: Names a linker script can carry on the left of an assignment.
#:
#: Wider than a C identifier -- ``.`` and ``$`` occur in real symbol names and
#: the linker accepts them -- but narrower than "anything", because the linker
#: tokenizes the name and may then try to parse part of it as a glob pattern.
#: Analyzer-generated labels are what run into this; symbols the binary really
#: named are already identifiers.
LINKER_SCRIPT_NAME_RE = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$]*$")


class ObjectArchMismatchError(RuntimeError):
    """Raised when compiled object code targets the wrong architecture."""


class UndefinedSymbolError(RuntimeError):
    """Raised when a linked patch object still references an undefined symbol."""


class UnsupportedRelocationError(RuntimeError):
    """Raised when a patch uses a relocation incompatible with its target."""


class Compiler:
    _NON_PREEMPTIBLE_SOURCE_HEADER = "#pragma GCC visibility push(hidden)\n"

    @staticmethod
    def linker_script_symbols(symbols: dict[str, int]) -> dict[str, int]:
        """
        Drop symbols whose names a linker script cannot carry.

        Analyzers name things the binary itself never named -- string contents,
        struct and array members -- and those names are not identifiers. The
        linker tokenizes the left side of an assignment and will try to read a
        bracketed run as a glob character class, so a name like
        ``s_[%s]_patient=%d_004022c7`` aborts the parse and takes the whole
        script with it, including every valid symbol. That fails the link for
        any patch, not just one referencing such a name.

        The rule is narrower than "contains a bracket" -- ``ElfComment[0]``
        parses fine -- but it depends on how the linker splits tokens, so this
        keeps to names patch code could actually reference and drops the rest.

        :param symbols: Merged symbols destined for the linker script.
        """
        usable, dropped = {}, []
        for name, addr in symbols.items():
            if LINKER_SCRIPT_NAME_RE.match(name):
                usable[name] = addr
            else:
                dropped.append(name)
        if dropped:
            logger.debug(
                "omitted %d symbol(s) from the linker script whose names it "
                "cannot parse: %s",
                len(dropped),
                ", ".join(sorted(dropped)[:5]),
            )
        return usable

    def __init__(self, p) -> None:
        self.p = p
        # preserve_none is a special attribute flag to allow us to control more registers as input to a C function
        self.preserve_none = False
        self._object_cache: dict[tuple[str, tuple[str, ...], str], bytes] = {}
        self._binary_symbols_cache: dict[str, int] | None = None

    def check_object_arch(self, elf) -> None:
        """Reject an ELF object that does not match the target archinfo."""
        expected = self.p.archinfo.elf_arch
        actual = {
            "e_machine": elf.header["e_machine"],
            "ei_class": elf.header["e_ident"]["EI_CLASS"],
            "ei_data": elf.header["e_ident"]["EI_DATA"],
        }
        mismatched = {
            key: (value, actual[key])
            for key, value in expected.items()
            if actual[key] != value
        }
        if mismatched:
            details = ", ".join(
                f"{key}: expected {want}, got {got}"
                for key, (want, got) in mismatched.items()
            )
            raise ObjectArchMismatchError(
                f"Compiled patch code does not match the target architecture "
                f"({details})"
            )

    def check_undefined_symbols(self, elf) -> None:
        """Reject linked patch objects that still reference undefined symbols."""
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return

        undefined = {
            index: symbol.name
            for index, symbol in enumerate(symtab.iter_symbols())
            if symbol.name and symbol.entry.st_shndx == "SHN_UNDEF"
        }
        unresolved = set()
        for section in elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            linked_symtab = elf.get_section(section["sh_link"])
            if linked_symtab is None or linked_symtab.name != symtab.name:
                continue
            for relocation in section.iter_relocations():
                symbol_name = undefined.get(relocation.entry.r_info_sym)
                if symbol_name is not None:
                    unresolved.add(symbol_name)

        if unresolved:
            raise UndefinedSymbolError(
                "Linked patch object references undefined symbols: "
                + ", ".join(sorted(unresolved))
            )

    def pic_compiler_flags(self) -> list[str]:
        if self.p.binfmt_tool.is_position_independent:
            return []

        flags = ["-fno-pic"]
        elf_arch = getattr(getattr(self.p, "archinfo", None), "elf_arch", {})
        if (
            elf_arch.get("e_machine") == "EM_MIPS"
            and elf_arch.get("ei_class") == "ELFCLASS64"
        ):
            flags.append("-mno-abicalls")
        return flags

    def check_got_relocations(self, elf, defined_symbols: set[str]) -> None:
        """Reject fixed-address relocations that require a GOT."""
        relocation_enum_names = {
            "EM_X86_64": "x64",
            "EM_386": "i386",
            "EM_AARCH64": "AARCH64",
            "EM_ARM": "ARM",
            "EM_MIPS": "MIPS",
            "EM_PPC": "PPC",
            "EM_PPC64": "PPC64",
            "EM_S390": "S390X",
        }
        enum_name = relocation_enum_names.get(elf.header["e_machine"])
        relocation_types = getattr(enums, f"ENUM_RELOC_TYPE_{enum_name}", {})
        relocation_names = {value: name for name, value in relocation_types.items()}
        invalid = set()

        for section in elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            linked_symtab = elf.get_section(section["sh_link"])
            if linked_symtab is None:
                continue
            for relocation in section.iter_relocations():
                symbol = linked_symtab.get_symbol(relocation.entry.r_info_sym)
                if symbol.name not in defined_symbols:
                    continue
                relocation_name = relocation_names.get(
                    relocation.entry.r_info_type,
                    f"type {relocation.entry.r_info_type}",
                )
                if (
                    "GOT" in relocation_name
                    or (
                        elf.header["e_machine"] == "EM_386"
                        and relocation.entry.r_info_type == 43  # R_386_GOT32X
                    )
                    or (
                        elf.header["e_machine"] == "EM_PPC64"
                        and section.name.endswith(".toc")
                    )
                ):
                    invalid.add((symbol.name, relocation_name, section.name))

        if invalid:
            details = ", ".join(
                f"{name} ({relocation} in {section})"
                for name, relocation, section in sorted(invalid)
            )
            raise UnsupportedRelocationError(
                "Fixed-address patch references absolute symbols through unsupported "
                f"relocations: {details}"
            )

    def compile(
        self,
        code: str,
        base=0,
        symbols: dict[str, int] | None = None,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        **kwargs,
    ) -> bytes:
        """
        :param extension: Source file extension, which is how clang decides how
            to read ``code``. ``.c`` for C, ``.ll`` for LLVM IR.
        """
        if symbols is None:
            symbols = {}
        if extra_compiler_flags is None:
            extra_compiler_flags = []
        if self.p.binfmt_tool.is_position_independent:
            code = self._NON_PREEMPTIBLE_SOURCE_HEADER + code
        compiler_flags = (
            tuple(self._compiler_flags)
            + tuple(self.pic_compiler_flags())
            + tuple(extra_compiler_flags)
        )
        # `extension` selects the source language, so it must key the cache too:
        # the same text compiled as C and as LLVM IR are different objects.
        object_key = (self._compiler, compiler_flags, code, extension)
        with tempfile.TemporaryDirectory() as td:
            object_path = os.path.join(td, "obj.o")
            object_bytes = self._object_cache.get(object_key)
            if object_bytes is None:
                source_path = os.path.join(td, f"code{extension}")
                with open(source_path, "w") as f:
                    f.write(code)
                try:
                    subprocess.run(
                        [
                            self._compiler,
                            *compiler_flags,
                            "-c",
                            source_path,
                            "-o",
                            object_path,
                        ],
                        check=True,
                        capture_output=True,
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise
                with open(object_path, "rb") as f:
                    object_bytes = f.read()
                self._object_cache[object_key] = object_bytes
            else:
                with open(object_path, "wb") as f:
                    f.write(object_bytes)

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            if self._binary_symbols_cache is None:
                self._binary_symbols_cache = {
                    name: symbol.addr
                    for name, symbol in self.p.binary_analyzer.get_all_symbols().items()
                }
            _symbols.update(self._binary_symbols_cache)
            _symbols.update(symbols)
            _symbols = self.linker_script_symbols(_symbols)

            # TODO: shouldn't put .rodata in .text, but otherwise switch case jump table won't work
            # Note that even we don't include .rodata here, cle might still include it if there is
            # no gap between .text and .rodata
            with io.BytesIO(object_bytes) as f:
                elf = ELFFile(f)
                self.check_got_relocations(elf, set(_symbols))
                self.check_object_arch(elf)
                linker_script_rodata_sections = " ".join(
                    [
                        f". = ALIGN({section['sh_addralign']}); *({section.name})"
                        for section in elf.iter_sections()
                        if section.name.startswith(".rodata")
                    ]
                )
            linker_script_symbols = "".join(
                f"{name} = {hex(addr)};" for name, addr in _symbols.items()
            )

            linker_script = f"SECTIONS {{ .patcherex2 : SUBALIGN(0) {{ . = {hex(base)}; *(.text) {linker_script_rodata_sections} {linker_script_symbols} }} }}"
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

            # link object file
            try:
                args = [self._linker] + [
                    "-relocatable",
                    os.path.join(td, "obj.o"),
                    "-T",
                    os.path.join(td, "linker.ld"),
                    "-o",
                    os.path.join(td, "obj_linked.o"),
                ]
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise
            with open(os.path.join(td, "obj_linked.o"), "rb") as f:
                self.check_undefined_symbols(ELFFile(f))

            # extract compiled code
            ld = cle.Loader(
                os.path.join(td, "obj_linked.o"), main_opts={"base_addr": 0x0}
            )

            patcherex2_section = next(
                (s for s in ld.main_object.sections if s.name == ".patcherex2"), None
            )
            compiled_start = ld.all_objects[0].entry + base

            compiled = ld.memory.load(
                compiled_start,
                patcherex2_section.memsize - compiled_start,
            )
        return compiled
