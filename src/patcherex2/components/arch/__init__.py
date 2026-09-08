from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Annotated

from pydantic import AfterValidator, Field

from patcherex2.models import FrozenPatcherexModel

JumpReachability = Callable[[int, int], bool]
RegisterMap = Mapping[str, Mapping[int, Sequence[str]]]


def _reject_zero(value: int) -> int:
    if value == 0:
        raise ValueError("instruction size cannot be zero")
    return value


InstructionSize = Annotated[int, Field(ge=-1), AfterValidator(_reject_zero)]


def mips_jump_is_reachable(source_addr: int, target_addr: int) -> bool:
    """Return whether a MIPS J-format jump stays within its 256 MiB region."""
    return ((source_addr + 4) & ~0x0FFFFFFF) == (target_addr & ~0x0FFFFFFF)


class ArchitectureInfo(FrozenPatcherexModel):
    """Immutable facts and policies shared by architecture-dependent components."""

    elf_arch: Mapping[str, str]
    nop_bytes: bytes
    nop_size: Annotated[int, Field(gt=0)]
    jmp_asm: str
    jmp_size: Annotated[int, Field(gt=0)]
    alignment: Annotated[int, Field(gt=0)]
    bits: Annotated[int, Field(gt=0)]
    is_variable_length_isa: bool
    instr_size: InstructionSize
    call_asm: str
    pc_reg_names: Sequence[str]
    save_context_asm: str
    restore_context_asm: str
    jmp_max_distance: Annotated[int, Field(ge=0)] | None = None
    jump_reachability: JumpReachability | None = None
    non_pic_compiler_flags: Sequence[str] = ()
    cc: Mapping[str, Sequence[str]] = Field(default_factory=dict)
    callee_saved: Mapping[str, Sequence[str]] = Field(default_factory=dict)
    cc_float: Mapping[str, Sequence[str]] = Field(default_factory=dict)
    callee_saved_float: Mapping[str, Sequence[str]] = Field(default_factory=dict)
    float_types: Mapping[int, str] = Field(default_factory=dict)
    subregisters: RegisterMap = Field(default_factory=dict)
    subregisters_float: RegisterMap = Field(default_factory=dict)

    @property
    def regs(self) -> list[str]:
        return list(self.subregisters)

    @property
    def regs_float(self) -> list[str]:
        return list(self.subregisters_float)

    def is_jump_reachable(self, source_addr: int, target_addr: int) -> bool:
        if self.jump_reachability is not None:
            return self.jump_reachability(source_addr, target_addr)
        if self.jmp_max_distance is None:
            return True
        return abs(target_addr - source_addr) <= self.jmp_max_distance
