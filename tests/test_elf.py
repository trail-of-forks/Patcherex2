import pytest
from elftools.elf.constants import P_FLAGS

from patcherex2.components.allocation_managers.allocation_manager import MemoryFlag
from patcherex2.components.binfmt_tools.elf import (
    memory_flags_from_elf_segment_flags,
)


@pytest.mark.parametrize(
    ("elf_flags", "expected"),
    [
        (0, MemoryFlag(0)),
        (P_FLAGS.PF_R, MemoryFlag.R),
        (P_FLAGS.PF_W, MemoryFlag.W),
        (P_FLAGS.PF_X, MemoryFlag.X),
        (P_FLAGS.PF_R | P_FLAGS.PF_W, MemoryFlag.RW),
        (P_FLAGS.PF_R | P_FLAGS.PF_X, MemoryFlag.RX),
        (P_FLAGS.PF_R | P_FLAGS.PF_W | P_FLAGS.PF_X, MemoryFlag.RWX),
    ],
)
def test_segment_permissions_are_preserved(elf_flags, expected):
    assert memory_flags_from_elf_segment_flags(elf_flags) == expected
