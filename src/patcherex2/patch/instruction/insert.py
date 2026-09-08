"""
Contains patches that modify the binary at the instruction level.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.allocation_manager import MemoryFlag
from patcherex2.patch import Patch

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from patcherex2.session import PatchSession


class InstructionPatchLanguage(Enum):
    """Source language accepted by an instruction insertion patch."""

    ASM = "ASM"
    C = "C"


@final
class InsertInstructionPatch(Patch):
    """Insert assembly or C through a trampoline, or create a named code block."""

    class CConfig:
        """Configuration for a C instruction micropatch."""

        def __init__(
            self,
            c_forward_header: str = "",
            scratch_regs: Iterable[str] | None = None,
            regs_sort: Iterable[str | tuple[str, int] | tuple[str, str]] | None = None,
            asm_header: str = "",
            asm_footer: str = "",
        ) -> None:
            """Initialize C micropatch configuration.

            Args:
                c_forward_header: Headers, types, and declarations prepended to the
                    generated C translation unit.
                scratch_regs: Registers the generated C code may freely clobber.
                regs_sort: Register exposure overrides. Entries may select a
                    subregister, a bit width, or a C type, such as ``"eax"``,
                    ``("xmm0", 32)``, or ``("xmm1", "double")``.
                asm_header: Assembly executed immediately before the C body.
                asm_footer: Assembly executed immediately after the C body.
            """
            self.c_forward_header: str = c_forward_header
            self.scratch_regs: Iterable[str] | None = scratch_regs
            self.regs_sort: Iterable[str | tuple[str, int] | tuple[str, str]] | None = regs_sort
            self.asm_header: str = asm_header
            self.asm_footer: str = asm_footer

    def __init__(
        self,
        addr_or_name: int | str,
        instr: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        is_thumb=False,
        *,
        language: InstructionPatchLanguage = InstructionPatchLanguage.ASM,
        c_config: CConfig | None = None,
        save_context: bool = False,
    ) -> None:
        """Initialize an instruction insertion.

        Args:
            addr_or_name: Runtime trampoline address, or a symbol name for a new
                standalone executable block.
            instr: Assembly or C source. Assembly symbol references use ``<name>``;
                assembly may also contain ``SAVE_CONTEXT`` and ``RESTORE_CONTEXT``.
            force_insert: Permit a trampoline when displaced instructions cannot
                otherwise be moved safely.
            detour_pos: Explicit runtime address for generated code, or ``-1`` to allocate.
            symbols: Explicit symbol addresses available during code generation.
            is_thumb: Generate a named assembly block in Thumb mode.
            language: Source language used by ``instr``.
            c_config: Configuration used when ``language`` is C.
            save_context: Preserve the architecture's configured register context.
        """
        if not isinstance(language, InstructionPatchLanguage):
            raise TypeError("language must be an InstructionPatchLanguage")
        self.addr_or_name: int | str = addr_or_name
        self.instr: str = instr
        self.force_insert: bool = force_insert
        self.detour_pos: int = detour_pos
        self.symbols: dict[str, int] = symbols or {}
        self.is_thumb: bool = is_thumb
        self.language: InstructionPatchLanguage = language
        self.c_config: InsertInstructionPatch.CConfig = c_config or InsertInstructionPatch.CConfig()
        self.save_context: bool = save_context

    @property
    def addr(self) -> int | None:
        return self.addr_or_name if isinstance(self.addr_or_name, int) else None

    @property
    def name(self) -> str | None:
        return self.addr_or_name if isinstance(self.addr_or_name, str) else None

    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the instruction insertion to a patch session."""
        match self.language:
            case InstructionPatchLanguage.ASM:
                self._apply_asm(p)
            case InstructionPatchLanguage.C:
                self._apply_c(p)

    def _apply_c(self, p: PatchSession) -> None:
        if self.addr is None:
            raise ValueError("An address must be provided for a C instruction patch")

        c_forward_header = self.c_config.c_forward_header
        c_scratch_regs = (
            frozenset()
            if self.c_config.scratch_regs is None
            else frozenset(self.c_config.scratch_regs)
        )
        c_regs_sort = [] if self.c_config.regs_sort is None else list(self.c_config.regs_sort)

        # TODO: make it os agnostic?
        calling_convention = (
            p.archinfo.cc["LinuxPreserveNone"]
            if p.compiler.preserve_none
            else p.archinfo.cc["Linux"]
        )
        subregister_table = p.archinfo.subregisters
        subregister_float_table = p.archinfo.subregisters_float

        # Figure out if there are any extra registers that we need to expose to the user
        # that aren't part of the calling convention. For x64 preserve_none, this will be
        # registers r10 and rbx.
        extra_saved = set(p.archinfo.regs)
        # Note that we cannot control callee saved registers. If we attempt to define
        # some registers via 'register uint64_t rbx asm("rbx");', the compiler will insert
        # push and pop instructions to save these registers.
        extra_saved = extra_saved - set(calling_convention) - set(p.archinfo.callee_saved["Linux"])
        extra_saved_in = list(extra_saved)
        # We don't want to necessarily output registers that have been marked as scratch
        # However we always want to make them available as input
        extra_saved_out = list(extra_saved - c_scratch_regs)

        def uint_converter(size: int):
            return f"uint{size}_t"

        extra_saved_in_converted = convert_to_subregisters(
            extra_saved_in, subregister_table, c_regs_sort, uint_converter
        )
        extra_saved_out_converted = convert_to_subregisters(
            extra_saved_out, subregister_table, c_regs_sort, uint_converter
        )

        calling_convention_float = p.archinfo.cc_float["Linux"]
        extra_saved_float = set(p.archinfo.regs_float)
        extra_saved_float = (
            extra_saved_float
            - set(calling_convention_float)
            - set(p.archinfo.callee_saved_float["Linux"])
        )
        extra_saved_float_in = list(extra_saved_float)
        extra_saved_float_out = list(extra_saved_float - c_scratch_regs)

        def float_converter(size: int):
            if size in p.archinfo.float_types:
                return p.archinfo.float_types[size]
            else:
                raise ValueError(f"Unable to determine type of float with size of {size} bits")

        extra_saved_float_in_converted = convert_to_subregisters(
            extra_saved_float_in, subregister_float_table, c_regs_sort, float_converter
        )
        extra_saved_float_out_converted = convert_to_subregisters(
            extra_saved_float_out, subregister_float_table, c_regs_sort, float_converter
        )

        attribute = "__attribute__((preserve_none))" if p.compiler.preserve_none else ""

        int_args = convert_to_subregisters(
            calling_convention, subregister_table, c_regs_sort, uint_converter
        )
        int_args_str = [f"{itype} {name}" for (name, itype) in int_args]
        float_args: list[tuple[str, str]] = convert_to_subregisters(
            calling_convention_float,
            subregister_float_table,
            c_regs_sort,
            float_converter,
        )
        float_args_str = [f"{ftype} {name}" for (name, ftype) in float_args]
        args_str = ", ".join(int_args_str + float_args_str)

        callback_forward_decl = f"extern void {attribute} _CALLBACK({args_str});"

        # Stupid macro tricks to make coding the patch a little bit nicer. This allows the user
        # to write 'return;' instead of having to understand how to call the callback
        # reg_name if reg_name in self.c_out_regs else '_dummy'
        return_macro_lines = [
            "#define return do {",
        ]

        for reg, _ in extra_saved_out_converted:
            # Make sure the variables are live just before the return statement
            return_macro_lines.append(f'    asm ("" : : "r"({reg}) :);')
        for reg, _ in extra_saved_float_out_converted:
            # Make sure the variables are live just before the return statement
            return_macro_lines.append(f'    asm ("" : : "r"({reg}) :);')

        callback_args = [
            "_dummy" if reg_name in c_scratch_regs else reg_name for (reg_name, bits) in int_args
        ]
        callback_args += [
            "_dummyFloat" if reg_name in c_scratch_regs else reg_name
            for (reg_name, ftype) in float_args
        ]
        return_macro_lines += [
            "    __attribute__((musttail)) return _CALLBACK({});".format(", ".join(callback_args)),
            "} while(0)",
        ]

        return_macro = "\\\n".join(return_macro_lines)

        lines = [
            "#include <stdint.h>",
            "",
            callback_forward_decl,
            "",
            c_forward_header,
            "",
            return_macro,
            "",
            f"void {attribute} _MICROPATCH({args_str}) {{",
            f"    uint{p.archinfo.bits}_t _dummy;",
            "    float _dummyFloat;",
        ]
        for reg, reg_type in extra_saved_in_converted:
            # Force the variables to live in a specific register using the register C extension
            lines.append(f'    register {reg_type} {reg} asm("{reg}");')
        for reg, ftype in extra_saved_float_in_converted:
            lines.append(f'    register {ftype} {reg} asm("{reg}");')
        for reg, _ in extra_saved_in_converted:
            # Trick the C compiler into thinking that the variables we just defined are actually live
            lines.append(f'    asm ("" : "=r"({reg}) : : );')
        for reg, _ in extra_saved_float_in_converted:
            lines.append(f'    asm ("" : "=r"({reg}) : : );')
        lines += [
            self.instr,
            # Make sure we actually do the callback in case the user forgets to put in a return
            "    return;",
            "}",
            "#undef return",
        ]
        code = "\n".join(lines)
        logger.info("InsertInstructionPatch generated C code:\n" + code)
        p.utils.insert_trampoline_code(
            self.addr,
            code,
            force_insert=self.force_insert,
            detour_pos=self.detour_pos,
            symbols=self.symbols,
            is_c=True,
            asm_header=self.c_config.asm_header,
            asm_footer=self.c_config.asm_footer,
        )

    def _apply_asm(self, p: PatchSession) -> None:
        if self.addr is not None:
            if "SAVE_CONTEXT" in self.instr:
                self.instr = self.instr.replace(
                    "SAVE_CONTEXT", f"\n{p.archinfo.save_context_asm}\n"
                )
            if "RESTORE_CONTEXT" in self.instr:
                self.instr = self.instr.replace(
                    "RESTORE_CONTEXT", f"\n{p.archinfo.restore_context_asm}\n"
                )
            if self.save_context:
                self.instr = (
                    f"{p.archinfo.save_context_asm}\n{self.instr}\n{p.archinfo.restore_context_asm}"
                )
            p.utils.insert_trampoline_code(
                self.addr,
                self.instr,
                force_insert=self.force_insert,
                detour_pos=self.detour_pos,
                symbols=self.symbols,
            )
        elif self.name:
            assemble_at = partial(
                p.assembler.assemble,
                self.instr,
                symbols=self.symbols,
                is_thumb=self.is_thumb,
            )

            assembled = assemble_at(0)
            if self.detour_pos == -1:
                block, assembled = p.utils.allocate_generated_code(
                    len(assembled),
                    assemble_at,
                    align=p.archinfo.alignment,
                    flag=MemoryFlag.RX,
                )
                mem_addr = block.mem_addr
                file_addr = block.file_addr
            else:
                mem_addr = self.detour_pos
                assembled = assemble_at(mem_addr)
                file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            p.symbols[self.name] = mem_addr
            p.image.update_binary_content(file_addr, assembled)


def convert_to_subregisters(
    cc: Sequence[str],
    subregisters: Mapping[str, Mapping[int, Sequence[str]]],
    regs_sort: list[str | tuple[str, int] | tuple[str, str]],
    type_converter: Callable[[int], str],
) -> list[tuple[str, str]]:
    regs = [r if isinstance(r, str) else r[0] for r in regs_sort]

    # reg_sizes maps registers to their size
    reg_sizes: dict[str, int] = {}
    # parent_regs maps all children registers to their largest parent register
    parent_regs: dict[str, str] = {}
    for parent, subregister_info in subregisters.items():
        for child_bits, children in subregister_info.items():
            for i, child in enumerate(children):
                if i > 0 and child in regs:
                    # Only allow the 0th subregister to actually be used.
                    raise ValueError(
                        f"Unable to create the calling convention when the {child} register is present. The {children[0]} subregister is the only {child_bits} bit subregister that can be used."
                    )
                reg_sizes[child] = child_bits
                parent_regs[child] = parent

    # The rewrites that should be applied to the cc to compute the transformed cc output
    rewrites: dict[str, tuple[str, str]] = {}
    for r in regs_sort:
        if isinstance(r, str):
            reg_name = r
            reg_bits = reg_sizes.get(reg_name)
            reg_type = None if reg_bits is None else type_converter(reg_bits)
        else:
            reg_name, register_type = r
            reg_type = (
                type_converter(register_type) if isinstance(register_type, int) else register_type
            )
        if reg_name in parent_regs:
            if reg_type is None:
                raise ValueError(f"Register {reg_name!r} has no known size")
            parent = parent_regs[reg_name]
            if parent in rewrites:
                raise ValueError(
                    f"The following two input registers overlapped while "
                    f"computing the calling convention: {reg_name} and "
                    f"{rewrites[parent][0]}"
                )
            rewrites[parent] = (reg_name, reg_type)

    def convert_cc_reg(cc_reg):
        if cc_reg in rewrites:
            return rewrites[cc_reg]
        else:
            parent_reg = parent_regs[cc_reg]
            parent_bits = reg_sizes[parent_reg]
            parent_type = type_converter(parent_bits)
            return (parent_reg, parent_type)

    return list(map(convert_cc_reg, cc))
