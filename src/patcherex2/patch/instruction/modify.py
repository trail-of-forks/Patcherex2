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
class ModifyInstructionPatch(Patch):
    """Overwrite instructions at a runtime address, padding with NOPs as needed."""

    def __init__(self, addr: int, instr: str, symbols: dict[str, int] | None = None) -> None:
        """Initialize an instruction modification.

        Args:
            addr: Runtime address of the first instruction to overwrite.
            instr: Replacement assembly. Symbol references use ``<name>``.
            symbols: Explicit symbol addresses available while assembling.
        """
        self.addr: int = addr
        self.instr: str = instr
        self.symbols: dict[str, int] = symbols if symbols else {}

    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the instruction modification to a patch session."""
        asm_bytes = p.assembler.assemble(
            self.instr,
            self.addr,
            symbols=self.symbols,
            is_thumb=p.binary_analyzer.is_thumb(self.addr),
        )
        if p.archinfo.is_variable_length_isa:
            asm_size = len(asm_bytes)
            overwritten_size = 0
            num_instrs = 1
            while overwritten_size < asm_size:
                instruction_bytes = p.binary_analyzer.get_instr_bytes_at(
                    self.addr, num_instr=num_instrs
                )
                if instruction_bytes is None:
                    raise ValueError(f"No instruction found at {hex(self.addr)}")
                overwritten_size = len(instruction_bytes)
                num_instrs += 1
            remaining_size = overwritten_size - asm_size
            assert remaining_size % p.archinfo.nop_size == 0, (
                f"Cannot fill in {remaining_size} bytes when modifying instruction, must be a multiple of {p.archinfo.nop_size}"
            )
            asm_bytes += p.archinfo.nop_bytes * (remaining_size // p.archinfo.nop_size)
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.image.update_binary_content(offset, asm_bytes)
