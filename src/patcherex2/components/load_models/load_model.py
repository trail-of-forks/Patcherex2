from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.patch.instruction import InsertInstructionPatch

if TYPE_CHECKING:
    from patcherex2.session import PatchSession


class LoadModel(ABC):
    """Describes how file-backed placements become runtime memory."""

    @abstractmethod
    def prepare(self, patcher: PatchSession) -> None:
        """Add any runtime initialization required before image finalization."""


class ArmBareMetalLoadModel(LoadModel):
    """Copies initialized writable allocations from flash to RAM on ARM."""

    def __init__(self, insert_points: Iterable[int]) -> None:
        self.insert_points = _normalize_insert_points(insert_points)

    @override
    def prepare(self, patcher: PatchSession) -> None:
        assembly = _copy_to_ram_assembly(patcher.allocation_manager.new_mapped_blocks)
        if not assembly:
            return
        if not self.insert_points:
            raise RuntimeError("Bare-metal initialized RAM needs at least one insert point")
        for insert_point in self.insert_points:
            InsertInstructionPatch(
                insert_point,
                assembly,
                save_context=True,
            ).apply(patcher)


def _normalize_insert_points(insert_points: Iterable[int]) -> list[int]:
    normalized = list(insert_points)
    if any(not isinstance(address, int) or address < 0 for address in normalized):
        raise ValueError("insert_points must contain non-negative integer addresses")
    return normalized


def _copy_to_ram_assembly(blocks) -> str:
    assembly = ""
    for index, block in enumerate(blocks):
        if block.mem_addr == block.load_mem_addr:
            continue
        label = f"patcherex_copy_{index}"
        assembly += f"""
ldr r0, ={hex(block.load_mem_addr)}
ldr r1, ={hex(block.mem_addr)}
ldr r2, ={hex(block.size)}
{label}:
ldrb r3, [r0], #1
strb r3, [r1], #1
subs r2, r2, #1
bne {label}
"""
    return assembly
