from types import SimpleNamespace

import pytest
from elftools.elf.constants import P_FLAGS

from patcherex2.components.allocation_managers.allocation_manager import (
    AllocationManager,
    MappedBlock,
    MemoryFlag,
)
from patcherex2.components.binfmt_tools.elf import (
    ELF,
    memory_flags_from_elf_segment_flags,
)
from patcherex2.components.utils.utils import Utils


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
def test_elf_segment_permissions_are_preserved(elf_flags, expected):
    assert memory_flags_from_elf_segment_flags(elf_flags) == expected


def make_elf_for_updates(size=32):
    elf = ELF.__new__(ELF)
    elf.file_updates = []
    elf.file_size = size
    elf.original_binary_content = bytes(range(size))
    return elf


@pytest.mark.parametrize(
    ("old_start", "old_end", "new_start", "new_end", "merged_start", "merged_end"),
    [
        (4, 8, 4, 8, 4, 8),
        (4, 8, 5, 7, 4, 8),
        (5, 7, 4, 8, 4, 8),
        (5, 9, 3, 7, 3, 9),
        (3, 7, 5, 9, 3, 9),
    ],
)
def test_idempotent_overlaps_merge(
    old_start, old_end, new_start, new_end, merged_start, merged_end
):
    elf = make_elf_for_updates()
    expected = elf.original_binary_content

    elf.update_binary_content(old_start, expected[old_start:old_end])
    elf.update_binary_content(new_start, expected[new_start:new_end])

    assert elf.file_updates == [
        {
            "offset": merged_start,
            "content": expected[merged_start:merged_end],
        }
    ]


def test_disjoint_updates_remain_separate_and_sorted():
    elf = make_elf_for_updates()

    elf.update_binary_content(12, b"cd")
    elf.update_binary_content(2, b"ab")

    assert elf.file_updates == [
        {"offset": 2, "content": b"ab"},
        {"offset": 12, "content": b"cd"},
    ]


@pytest.mark.parametrize(
    ("old_start", "old_content", "new_start", "new_content"),
    [
        (4, b"abcd", 5, b"XX"),
        (5, b"bc", 4, b"aXXd"),
        (5, b"bcd", 3, b"abX"),
        (3, b"abc", 5, b"XXd"),
    ],
)
def test_conflicting_overlaps_are_rejected_in_both_directions(
    old_start, old_content, new_start, new_content
):
    elf = make_elf_for_updates()
    elf.update_binary_content(old_start, old_content)

    with pytest.raises(ValueError, match="conflicts with a previous update interval"):
        elf.update_binary_content(new_start, new_content)

    assert elf.file_updates == [{"offset": old_start, "content": old_content}]


def test_empty_update_is_a_noop_and_negative_offset_is_rejected():
    elf = make_elf_for_updates()

    elf.update_binary_content(4, b"")
    assert elf.file_updates == []

    with pytest.raises(ValueError, match="negative file offset"):
        elf.update_binary_content(-1, b"x")


def test_aligned_allocation_can_be_freed_and_reused_at_its_original_address():
    manager = AllocationManager(SimpleNamespace())
    manager.add_block(
        MappedBlock(
            file_addr=0x100,
            mem_addr=0x1002,
            size=0x20,
            is_free=True,
            flag=MemoryFlag.RWX,
        )
    )

    first = manager._find_in_mapped_blocks(
        0x10,
        flag=MemoryFlag.RX,
        align=4,
    )
    assert first.mem_addr == 0x1004
    assert first.size == 0x10
    assert first.flag == MemoryFlag.RWX

    manager.free(first)
    assert len(manager.blocks[MappedBlock]) == 1
    restored = manager.blocks[MappedBlock][0]
    assert restored.file_addr == 0x100
    assert restored.mem_addr == 0x1002
    assert restored.size == 0x20
    assert restored.is_free
    assert restored.flag == MemoryFlag.RWX

    second = manager._find_in_mapped_blocks(
        0x12,
        flag=MemoryFlag.RX,
        align=4,
    )
    assert second.mem_addr == first.mem_addr
    assert second.size == 0x12


def test_allocated_block_adjacent_to_occupied_block_remains_tracked():
    manager = AllocationManager(SimpleNamespace())
    occupied = MappedBlock(
        file_addr=0x100,
        mem_addr=0x1000,
        size=0x10,
        is_free=False,
        flag=MemoryFlag.RX,
    )
    manager.add_block(occupied)
    manager.add_block(
        MappedBlock(
            file_addr=0x110,
            mem_addr=0x1010,
            size=0x20,
            is_free=True,
            flag=MemoryFlag.RX,
        )
    )

    allocated = manager._find_in_mapped_blocks(0x10, flag=MemoryFlag.RX)

    assert allocated in manager.blocks[MappedBlock]
    assert occupied.size == 0x10

    manager.free(allocated)
    assert manager.blocks[MappedBlock] == [occupied, allocated]
    assert allocated.file_addr == 0x110
    assert allocated.mem_addr == 0x1010
    assert allocated.size == 0x20
    assert allocated.is_free


class FakeAllocationManager:
    def __init__(self):
        self.requests = []
        self.freed = []

    def allocate(self, size, **kwargs):
        self.requests.append((size, kwargs))
        index = len(self.requests)
        return SimpleNamespace(
            mem_addr=index * 0x1000,
            file_addr=index * 0x100,
            size=size,
            is_free=False,
        )

    def free(self, block):
        block.is_free = True
        self.freed.append(block)


def test_trampoline_allocation_reassembles_until_final_bytes_fit():
    allocation_manager = FakeAllocationManager()
    patcher = SimpleNamespace(
        allocation_manager=allocation_manager,
        archinfo=SimpleNamespace(alignment=1),
        binfmt_tool=SimpleNamespace(is_position_independent=True),
    )
    utils = Utils(patcher, "unused")

    final_sizes = {0x1000: 26, 0x2000: 28, 0x3000: 28}

    block, content = utils._allocate_trampoline(
        0x4000,
        24,
        lambda mem_addr: b"X" * final_sizes[mem_addr],
    )

    assert [request[0] for request in allocation_manager.requests] == [24, 26, 28]
    assert len(allocation_manager.freed) == 2
    assert block.mem_addr == 0x3000
    assert block.size == len(content) == 28
    for _, kwargs in allocation_manager.requests:
        assert kwargs["flag"] == MemoryFlag.RX
        assert kwargs["near_addr"] == 0x4000
