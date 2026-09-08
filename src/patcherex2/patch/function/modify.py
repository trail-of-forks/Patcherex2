from __future__ import annotations

import logging
import sys
from collections.abc import Callable
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
class ModifyFunctionPatch(Patch):
    """Replace a function in place or redirect it to newly allocated code."""

    def __init__(
        self,
        addr_or_name: int | str,
        code: str,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        **kwargs,
    ) -> None:
        """Initialize a function replacement.

        Args:
            addr_or_name: Function name or runtime address.
            code: Replacement C source.
            detour_pos: Explicit address for an out-of-line replacement, or ``-1``
                to allocate it.
            symbols: Explicit symbols available while compiling.
            **kwargs: Compiler arguments in ``compile_opts``.
        """
        self.code = code
        self.detour_pos = detour_pos
        self.addr_or_name = addr_or_name
        self.symbols = symbols if symbols else {}
        self.compile_opts = kwargs.get("compile_opts", {})

    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the function replacement to a patch session."""
        func = p.binary_analyzer.get_function(self.addr_or_name)
        if func is None:
            raise ValueError(f"Function {self.addr_or_name!r} was not found")
        func_addr = func.addr
        is_thumb = p.binary_analyzer.is_thumb(func_addr)

        compile_at = partial(
            p.compiler.compile,
            self.code,
            symbols=self.symbols,
            is_thumb=is_thumb,
            **self.compile_opts,
        )

        compiled = compile_at(func_addr)
        if len(compiled) <= func.size:
            file_addr = p.binary_analyzer.mem_addr_to_file_offset(func_addr)
            p.image.update_binary_content(file_addr, compiled)
            return

        mem_addr, file_addr, compiled = self._create_detour_target(
            p,
            func_addr,
            compiled,
            compile_at,
        )
        self._install_detour(
            p,
            source_addr=func_addr,
            target_addr=mem_addr,
            is_thumb=is_thumb,
        )
        p.image.update_binary_content(file_addr, compiled)

    def _create_detour_target(
        self,
        p: PatchSession,
        source_addr: int,
        initial_compiled: bytes,
        compile_at: Callable[[int], bytes],
    ) -> tuple[int, int, bytes]:
        if self.detour_pos != -1:
            mem_addr = self.detour_pos
            compiled = compile_at(mem_addr)
            file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            return mem_addr, file_addr, compiled

        block, compiled = p.utils.allocate_generated_code(
            len(initial_compiled),
            compile_at,
            align=p.archinfo.alignment,
            flag=MemoryFlag.RX,
            allocation_options=lambda _requested_size: p.utils.jump_allocation_options(source_addr),
        )
        return block.mem_addr, block.file_addr, compiled

    def _install_detour(
        self,
        p: PatchSession,
        source_addr: int,
        target_addr: int,
        is_thumb: bool,
    ) -> None:
        p.utils.validate_jump_reachability(source_addr, target_addr)
        jmp_bytes = p.assembler.assemble(
            p.archinfo.jmp_asm.format(dst=hex(target_addr)),
            source_addr,
            is_thumb=is_thumb,
        )
        p.image.update_binary_content(
            p.binary_analyzer.mem_addr_to_file_offset(source_addr),
            jmp_bytes,
        )
