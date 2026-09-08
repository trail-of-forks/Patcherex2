"""
Contains patches that modify the binary at the function level.
"""

from __future__ import annotations

import logging
import sys
from functools import partial
from typing import TYPE_CHECKING, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.allocation_manager import MemoryFlag
from patcherex2.patch import Patch

if TYPE_CHECKING:
    from patcherex2.session import PatchSession

logger = logging.getLogger(__name__)


@final
class InsertFunctionPatch(Patch):
    """Insert a named function or call a new function from an existing address."""

    def __init__(
        self,
        addr_or_name: int | str,
        code: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        is_thumb=False,
        **kwargs,
    ) -> None:
        """Initialize a function insertion.

        Args:
            addr_or_name: Runtime address at which to install a call, or a symbol
                name for a new standalone function.
            code: C source defining the new function.
            force_insert: Permit insertion when displaced instructions cannot
                otherwise be moved safely.
            detour_pos: Explicit address for generated code, or ``-1`` to allocate.
            symbols: Explicit symbols available while compiling and assembling.
            is_thumb: Compile a named function for Thumb mode.
            **kwargs: Address-based hook assembly in ``prefunc`` and ``postfunc``,
                a ``save_context`` boolean, and compiler arguments in ``compile_opts``.
        """
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.code = code
        self.detour_pos = detour_pos
        self.symbols = symbols if symbols else {}
        self.is_thumb = is_thumb
        self.force_insert = force_insert
        self.prefunc = kwargs.get("prefunc", None)
        self.postfunc = kwargs.get("postfunc", None)
        self.compile_opts = kwargs.get("compile_opts", {})
        self.save_context = kwargs.get("save_context", False)

    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the function insertion to a patch session."""
        if self.addr is not None:
            self._apply_at_address(p, self.addr)
            return
        if self.name:
            self._apply_named(p, self.name)

    def _apply_at_address(self, p: PatchSession, addr: int) -> None:
        prefunc = self._expand_context_macros(p, self.prefunc)
        postfunc = self._expand_context_macros(p, self.postfunc)
        function_name = f"__patcherex_{hex(addr)}"

        InsertFunctionPatch(
            function_name,
            self.code,
            is_thumb=p.binary_analyzer.is_thumb(addr),
            symbols=self.symbols,
            compile_opts=self.compile_opts,
        ).apply(p)

        instrs = ""
        instrs += p.archinfo.save_context_asm if self.save_context else ""
        instrs += prefunc
        instrs += "\n"
        # NOTE: This is hardcoded to bl, not blx, but it is valid for this use case.
        instrs += p.archinfo.call_asm.format(dst=f"<{function_name}>")
        instrs += "\n"
        instrs += postfunc
        instrs += p.archinfo.restore_context_asm if self.save_context else ""
        p.utils.insert_trampoline_code(
            addr,
            instrs,
            force_insert=self.force_insert,
            detour_pos=self.detour_pos,
            symbols=self.symbols,
        )

    @staticmethod
    def _expand_context_macros(
        p: PatchSession,
        instrs: str | None,
    ) -> str:
        if not instrs:
            return ""
        return instrs.replace(
            "SAVE_CONTEXT",
            f"\n{p.archinfo.save_context_asm}\n",
        ).replace(
            "RESTORE_CONTEXT",
            f"\n{p.archinfo.restore_context_asm}\n",
        )

    def _apply_named(self, p: PatchSession, name: str) -> None:
        compile_at = partial(
            p.compiler.compile,
            self.code,
            symbols=self.symbols,
            is_thumb=self.is_thumb,
            **self.compile_opts,
        )

        compiled = compile_at(0)
        if self.detour_pos == -1:
            block, compiled = p.utils.allocate_generated_code(
                len(compiled),
                compile_at,
                align=p.archinfo.alignment,
                flag=MemoryFlag.RX,
            )
            mem_addr = block.mem_addr
            file_addr = block.file_addr
        else:
            mem_addr = self.detour_pos
            compiled = compile_at(mem_addr)
            file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)

        p.added_functions.append(hex(mem_addr))
        # Register a Thumb function with the Thumb bit set. The ARM compiler
        # decides whether a call target is Thumb by testing `target + 1`
        # against p.symbols.values().
        # Without the bit, a Thumb caller's BLX to this function is left as BLX,
        # which switches to ARM mode and faults on a Thumb-only core such as
        # Cortex-M.
        p.symbols[name] = (mem_addr | 1) if self.is_thumb else mem_addr
        p.image.update_binary_content(file_addr, compiled)
