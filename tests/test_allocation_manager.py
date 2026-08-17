from types import SimpleNamespace

import pytest

from patcherex2.components.allocation_managers.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from patcherex2.targets.elf_arm_bare import (
    CustomAllocationManager,
    FlashBlock,
    RamBlock,
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


def test_open_end_large_allocation_checks_later_validator_candidates():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x2000, -1))
    manager.add_block(MemoryBlock(0x3000, -1))

    block = manager.allocate(
        AllocationManager.CHUNK + 1,
        flag=MemoryFlag.RX,
        align=4,
        near_addr=0x1000,
        max_dist=0x3000,
        address_validator=lambda addr: addr == 0x4000,
    )

    assert block.file_addr == 0x3000
    assert block.mem_addr == 0x4000
    assert manager.new_mapped_blocks[0].size == AllocationManager.CHUNK + 0x1001


def test_open_end_allocation_searches_near_distant_preference():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x1000, -1))
    manager.add_block(MemoryBlock(0x2000, -1))

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        near_addr=0x22000,
        max_dist=0,
        address_validator=lambda addr: addr == 0x22000,
    )

    assert block.file_addr == 0x21000
    assert block.mem_addr == 0x22000


def test_open_end_allocation_falls_back_when_preferred_window_is_invalid():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x1000, -1))
    manager.add_block(MemoryBlock(0x2000, -1))

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        near_addr=0x100000,
        address_validator=lambda addr: addr == 0x2000,
    )

    assert block.file_addr == 0x1000
    assert block.mem_addr == 0x2000


def test_open_end_allocation_handles_alignment_larger_than_search_window():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0, -1))
    manager.add_block(MemoryBlock(0, -1))

    block = manager.allocate(
        1,
        flag=MemoryFlag.RX,
        align=0x30000,
        near_addr=0x18000,
        address_validator=lambda addr: addr == 0,
    )

    assert block.file_addr == 0
    assert block.mem_addr == 0


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


def test_validator_without_near_address_can_use_finite_gap():
    binfmt_tool = SimpleNamespace(
        file_size=0x1000,
        page_alignment=lambda: 0x1000,
    )
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x1000, -1))
    manager.add_block(MemoryBlock(0x2000, 0x1000))
    manager.add_block(MemoryBlock(0x30000, -1))

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        address_validator=lambda addr: addr == 0x2000,
    )

    assert block.file_addr == 0x1000
    assert block.mem_addr == 0x2000


def test_gap_allocation_checks_farther_candidate_after_validator_rejection():
    binfmt_tool = SimpleNamespace(
        file_size=0xF00,
        page_alignment=lambda: 0x1000,
    )
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0xF00, -1))
    manager.add_block(MemoryBlock(0x1000, 0x3000))

    block = manager.allocate(
        0x20,
        flag=MemoryFlag.RX,
        align=4,
        near_addr=0x5000,
        address_validator=lambda addr: addr == 0x2F00,
    )

    assert block.file_addr == 0xF00
    assert block.mem_addr == 0x2F00


def test_existing_mapped_block_checks_farther_validator_candidates():
    manager = AllocationManager(SimpleNamespace())
    manager.add_block(
        MappedBlock(
            file_addr=0x1000,
            mem_addr=0x1000,
            size=0x2000,
            is_free=True,
            flag=MemoryFlag.RX,
        )
    )

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        near_addr=0x4000,
        max_dist=0x1010,
        address_validator=lambda addr: addr == 0x2FF8,
    )

    assert block.file_addr == 0x2FF8
    assert block.mem_addr == 0x2FF8
    assert manager.new_mapped_blocks == []


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


def test_failed_aligned_allocation_does_not_advance_open_end():
    binfmt_tool = SimpleNamespace(page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    file_block = FileBlock(0x2003, -1)
    memory_block = MemoryBlock(0x3000, -1)
    manager.add_block(file_block)
    manager.add_block(memory_block)

    with pytest.raises(MemoryError, match="Insufficient memory"):
        manager.allocate(
            1,
            flag=MemoryFlag.RX,
            align=4,
            near_addr=0x3003,
            max_dist=0,
        )

    assert file_block.addr == 0x2003
    assert memory_block.addr == 0x3000
    assert manager.new_mapped_blocks == []


def test_custom_allocator_preserves_rw_load_address():
    binfmt_tool = SimpleNamespace(
        page_alignment=lambda: 0x1000,
        flash_end=0x100000,
        ram_end=0x200000,
    )
    manager = CustomAllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0x1000, -1))
    manager.add_block(FlashBlock(0x2000, -1))
    manager.add_block(RamBlock(0x4000, -1))

    block = manager.allocate(
        0x20,
        flag=MemoryFlag.RW,
        align=4,
        near_addr=0x3000,
        max_dist=0x1000,
        address_validator=lambda addr: addr == 0x4000,
    )

    assert block.file_addr == 0x1000
    assert block.mem_addr == 0x4000
    assert block.load_mem_addr == 0x2000
    assert manager.new_mapped_blocks[0].load_mem_addr == 0x2000

    manager.free(block)
    assert len(manager.blocks[MappedBlock]) == 1
    restored = manager.blocks[MappedBlock][0]
    assert restored.mem_addr == 0x4000
    assert restored.load_mem_addr == 0x2000
    assert restored.size == AllocationManager.CHUNK


def test_custom_allocator_rejects_allocation_past_flash_end():
    binfmt_tool = SimpleNamespace(
        page_alignment=lambda: 0x1000,
        flash_end=0x12000,
    )
    manager = CustomAllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    file_block = FileBlock(0x1000, -1)
    flash_block = FlashBlock(0x2000, -1)
    manager.add_block(file_block)
    manager.add_block(flash_block)

    with pytest.raises(MemoryError, match="Insufficient memory"):
        manager.allocate(
            4,
            flag=MemoryFlag.RX,
            align=4,
            near_addr=0x12000,
            max_dist=0,
            address_validator=lambda addr: addr == 0x12000,
        )

    assert file_block.addr == 0x1000
    assert flash_block.addr == 0x2000
    assert manager.new_mapped_blocks == []


def test_custom_allocator_sizes_region_for_large_request():
    binfmt_tool = SimpleNamespace(
        page_alignment=lambda: 0x1000,
        flash_end=0x100000,
    )
    manager = CustomAllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    file_block = FileBlock(0x1000, -1)
    flash_block = FlashBlock(0x2000, -1)
    manager.add_block(file_block)
    manager.add_block(flash_block)

    block = manager.allocate(
        AllocationManager.CHUNK + 1,
        flag=MemoryFlag.RX,
    )

    assert block.size == AllocationManager.CHUNK + 1
    assert manager.new_mapped_blocks[0].size == block.size
    assert file_block.addr == 0x1000 + block.size
    assert flash_block.addr == 0x2000 + block.size


def test_finalize_trims_extents_across_coalesced_free_blocks():
    binfmt_tool = SimpleNamespace(file_size=0, page_alignment=lambda: 0x1000)
    manager = AllocationManager(SimpleNamespace(binfmt_tool=binfmt_tool))
    manager.add_block(FileBlock(0, -1))
    manager.add_block(MemoryBlock(0, -1))

    first = manager.allocate(0x10, flag=MemoryFlag.RX)
    second = manager.allocate(
        0x10,
        flag=MemoryFlag.RX,
        align=0x10,
        near_addr=0x11000,
        max_dist=0,
        address_validator=lambda addr: addr == 0x11000,
    )
    assert first.mem_addr == 0
    assert second.mem_addr == 0x11000

    manager.finalize()

    assert [block.size for block in manager.new_mapped_blocks] == [0x10, 0x1010]
    assert binfmt_tool.file_size == 0x11010
