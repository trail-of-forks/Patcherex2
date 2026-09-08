from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, final

from patcherex2.components.disassemblers.disassembler import Disassembler
from patcherex2.components.symbol_resolver import SymbolResolver

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import Assembler
from patcherex2.components.compilers import Compiler

if TYPE_CHECKING:
    from patcherex2.components.assembler import Assembler
    from patcherex2.components.disassemblers.disassembler import Disassembler
    from patcherex2.components.symbol_resolver import SymbolResolver


@final
class ArmCompiler(Compiler):
    """Add ARM/Thumb mode handling to another compiler."""

    def __init__(
        self,
        compiler: Compiler,
        assembler: Assembler,
        disassembler: Disassembler,
        symbol_resolver: SymbolResolver,
    ) -> None:
        self.compiler: Compiler = compiler
        self.assembler: Assembler = assembler
        self.disassembler: Disassembler = disassembler
        self.symbol_resolver: SymbolResolver = symbol_resolver
        self.preserve_none = compiler.preserve_none

    @override
    def compile(
        self,
        code: str,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        is_thumb: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """Compile and correct calls that cross the ARM/Thumb mode boundary."""
        compiler_flags = list(extra_compiler_flags or ())
        compiler_flags.append("-mthumb" if is_thumb else "-mno-thumb")
        compiled = self.compiler.compile(
            code,
            base=base,
            symbols=symbols,
            extension=extension,
            extra_compiler_flags=compiler_flags,
            is_thumb=is_thumb,
            **kwargs,
        )
        resolved_symbols = self.symbol_resolver.resolve(symbols)
        return self._correct_mode_switches(
            compiled,
            base,
            set(resolved_symbols.values()),
            is_thumb,
        )

    def _correct_mode_switches(
        self,
        compiled: bytes,
        base: int,
        symbol_addresses: set[int],
        is_thumb: bool,
    ) -> bytes:
        rewritten = bytearray()
        instructions = self.disassembler.disassemble(
            compiled,
            base=base,
            is_thumb=is_thumb,
        )
        for instruction in instructions:
            replacement = self._replacement_mnemonic(
                instruction,
                symbol_addresses,
                is_thumb,
            )
            if replacement is None:
                start = instruction["address"] - base
                rewritten.extend(compiled[start : start + instruction["size"]])
                continue
            assembly = self.disassembler.to_asm_string(instruction).replace(
                instruction["mnemonic"],
                replacement,
                1,
            )
            rewritten.extend(
                self.assembler.assemble(
                    f"{assembly}\n",
                    base=instruction["address"],
                    is_thumb=is_thumb,
                )
            )
        rewritten.extend(compiled[len(rewritten) :])
        if len(rewritten) % 2:
            rewritten.append(0)
        return bytes(rewritten)

    @staticmethod
    def _replacement_mnemonic(
        instruction: Mapping[str, Any],
        symbol_addresses: set[int],
        is_thumb: bool,
    ) -> str | None:
        mnemonic = instruction["mnemonic"]
        if mnemonic not in {"bl", "blx"}:
            return None
        target = int(instruction["op_str"][1:], 0)
        if target + 1 in symbol_addresses:
            target_is_thumb = True
        elif target in symbol_addresses:
            target_is_thumb = False
        else:
            return None
        desired_mnemonic = "bl" if target_is_thumb == is_thumb else "blx"
        return None if mnemonic == desired_mnemonic else desired_mnemonic
