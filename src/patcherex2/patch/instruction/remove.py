"""
Contains patches that modify the binary at the instruction level.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.patch import Patch

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from patcherex2.session import PatchSession


@final
class RemoveInstructionPatch(Patch):
    """Replaces a decoded instruction count or an exact byte range with NOPs."""

    def __init__(
        self,
        addr: int,
        num_instr: int | None = None,
        num_bytes: int | None = None,
    ) -> None:
        """Initialize an instruction removal.

        Args:
            addr: Runtime address of the first instruction.
            num_instr: Number of complete decoded instructions to replace.
            num_bytes: Exact byte count to replace; it must fit whole NOPs.
        """
        self.addr: int = addr
        self.num_instr: int | None = num_instr
        self.num_bytes: int | None = num_bytes
        if self.num_instr is not None and self.num_bytes is not None:
            raise ValueError("Specify either num_instr or num_bytes, not both")
        if self.num_instr is None and self.num_bytes is None:
            self.num_instr = 1

    @override
    def apply(self, p: PatchSession) -> None:
        """Replace the selected instruction range with architecture NOPs."""
        num_bytes = self.num_bytes
        if num_bytes is None:
            if self.num_instr is None or self.num_instr <= 0:
                raise ValueError("num_instr must be positive")
            instruction_bytes = p.binary_analyzer.get_instr_bytes_at(
                self.addr,
                num_instr=self.num_instr,
            )
            if instruction_bytes is None:
                raise ValueError(f"No instruction found at {hex(self.addr)}")
            num_bytes = len(instruction_bytes)
        if num_bytes <= 0 or num_bytes % p.archinfo.nop_size != 0:
            raise ValueError(
                f"Cannot remove {num_bytes} bytes, must be a positive multiple of {p.archinfo.nop_size}"
            )
        num_nops = num_bytes // p.archinfo.nop_size
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.image.update_binary_content(offset, p.archinfo.nop_bytes * num_nops)
