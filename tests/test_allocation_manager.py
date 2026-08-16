from types import SimpleNamespace

import pytest

from patcherex2.components.allocation_managers.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)


def test_open_end_allocation_honors_reachable_max_distance():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x2000, -1))
    manager.add_block(MemoryBlock(0x3000, -1))

    block = manager.allocate(
        0x20,
        flag=MemoryFlag.RX,
        near_addr=0x1000,
        max_dist=0x2000,
    )

    assert block.file_addr == 0x2000
    assert block.mem_addr == 0x3000


def test_gap_allocation_appends_at_file_end_with_compatible_memory_address():
    binfmt_tool = SimpleNamespace(
        file_size=0x1234,
        minimum_memory_address_for_new_segment=lambda offset: offset + 0x1000,
        page_alignment=lambda: 0x1000,
    )
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x1234, -1))
    manager.add_block(MemoryBlock(0x1000, 0x5000))
    manager.add_block(MemoryBlock(0x8000, -1))

    block = manager.allocate(
        0x20,
        flag=MemoryFlag.RX,
        near_addr=0x1200,
        max_dist=0x2000,
    )

    assert block.file_addr == 0x1234
    assert block.mem_addr == 0x2234
    assert block.mem_addr - block.file_addr == 0x1000


def test_open_end_allocation_rejects_unreachable_max_distance():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    file_block = FileBlock(0x2000, -1)
    memory_block = MemoryBlock(0x3000, -1)
    manager.add_block(file_block)
    manager.add_block(memory_block)

    with pytest.raises(MemoryError, match="Insufficient memory"):
        manager.allocate(
            0x20,
            flag=MemoryFlag.RX,
            near_addr=0x1000,
            max_dist=0x1FFF,
        )

    assert file_block.addr == 0x2000
    assert memory_block.addr == 0x3000


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
