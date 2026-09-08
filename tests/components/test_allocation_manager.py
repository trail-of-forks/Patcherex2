import pytest

from patcherex2.components.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from patcherex2.components.placement_strategies import (
    ElfBareMetalAllocationExtender,
    FlashBlock,
    RamBlock,
)
from tests.support.fakes import FakeBinaryAnalyzer, FakeImageBackend


def make_manager(image=None, extender=None):
    if image is None:
        image = FakeImageBackend()
    return AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=image,
        extender=extender,
    )


def test_finalize_discards_an_entirely_freed_new_extent():
    manager = make_manager()
    manager.add_block(FileBlock(addr=0x2000, size=-1))
    manager.add_block(MemoryBlock(addr=0x3000, size=-1))
    block = manager.allocate(16, flag=MemoryFlag.RX)
    manager.free(block)
    manager.finalize()
    assert manager.new_mapped_blocks == []
    assert manager.blocks[MappedBlock] == []


def test_open_end_allocation_honors_reachable_max_distance():
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x2000, size=-1))
    manager.add_block(MemoryBlock(addr=0x3000, size=-1))

    block = manager.allocate(
        0x20,
        flag=MemoryFlag.RX,
        near_addr=0x1000,
        max_dist=0x2000,
    )

    assert block.file_addr == 0x2000
    assert block.mem_addr == 0x3000


@pytest.mark.parametrize(
    ("size", "options", "message"),
    [
        (0, {}, "(?s)size.*greater than 0"),
        (1, {"align": 0}, "(?s)align.*greater than 0"),
        (1, {"max_dist": -1}, "(?s)max_dist.*greater than or equal to 0"),
    ],
)
def test_invalid_allocation_request_is_rejected(size, options, message):
    manager = make_manager()

    with pytest.raises(ValueError, match=message):
        manager.allocate(size, **options)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("r", MemoryFlag.R),
        ("xR", MemoryFlag.RX),
        ("RWX", MemoryFlag.RWX),
        (MemoryFlag.RW, MemoryFlag.RW),
    ],
)
def test_memory_flags_are_normalized(value, expected):
    assert MemoryFlag.parse(value) == expected


def test_undefined_memory_flag_does_not_alias_execute():
    assert MemoryFlag.UNDEF == MemoryFlag(0)
    assert MemoryFlag.UNDEF != MemoryFlag.X


@pytest.mark.parametrize("value", ["", "read", object()])
def test_invalid_memory_flags_are_rejected(value):
    with pytest.raises((TypeError, ValueError)):
        MemoryFlag.parse(value)


def test_open_end_large_allocation_checks_later_validator_candidates():
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x2000, size=-1))
    manager.add_block(MemoryBlock(addr=0x3000, size=-1))

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
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x1000, size=-1))
    manager.add_block(MemoryBlock(addr=0x2000, size=-1))

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
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x1000, size=-1))
    manager.add_block(MemoryBlock(addr=0x2000, size=-1))

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
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0, size=-1))
    manager.add_block(MemoryBlock(addr=0, size=-1))

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
    image = FakeImageBackend(
        file_size=0x1234,
        minimum_address=lambda offset: offset + 0x1000,
    )
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x1234, size=-1))
    manager.add_block(MemoryBlock(addr=0x1000, size=0x5000))
    manager.add_block(MemoryBlock(addr=0x8000, size=-1))

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
    image = FakeImageBackend(
        file_size=0x1000,
    )
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0x1000, size=-1))
    manager.add_block(MemoryBlock(addr=0x2000, size=0x1000))
    manager.add_block(MemoryBlock(addr=0x30000, size=-1))

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        address_validator=lambda addr: addr == 0x2000,
    )

    assert block.file_addr == 0x1000
    assert block.mem_addr == 0x2000


def test_gap_allocation_checks_farther_candidate_after_validator_rejection():
    image = FakeImageBackend(
        file_size=0xF00,
    )
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0xF00, size=-1))
    manager.add_block(MemoryBlock(addr=0x1000, size=0x3000))

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
    manager = make_manager()
    manager.add_block(
        MappedBlock(
            file_addr=0x1000,
            addr=0x1000,
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
    image = FakeImageBackend()
    manager = make_manager(image)
    file_block = FileBlock(addr=0x2000, size=-1)
    memory_block = MemoryBlock(addr=0x3000, size=-1)
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
    manager = make_manager()
    manager.add_block(
        MappedBlock(
            file_addr=0x100,
            addr=0x1002,
            size=0x20,
            is_free=True,
            flag=MemoryFlag.RWX,
        )
    )

    first = manager.allocate(
        0x10,
        flag=MemoryFlag.RX,
        align=4,
    )
    assert first.mem_addr == 0x1004
    assert first.addr == first.mem_addr
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

    second = manager.allocate(
        0x12,
        flag=MemoryFlag.RX,
        align=4,
    )
    assert second.mem_addr == first.mem_addr
    assert second.size == 0x12


def test_allocated_block_adjacent_to_occupied_block_remains_tracked():
    manager = make_manager()
    occupied = MappedBlock(
        file_addr=0x100,
        addr=0x1000,
        size=0x10,
        is_free=False,
        flag=MemoryFlag.RX,
    )
    manager.add_block(occupied)
    manager.add_block(
        MappedBlock(
            file_addr=0x110,
            addr=0x1010,
            size=0x20,
            is_free=True,
            flag=MemoryFlag.RX,
        )
    )

    allocated = manager.allocate(0x10, flag=MemoryFlag.RX)

    assert allocated in manager.blocks[MappedBlock]
    assert occupied.size == 0x10

    manager.free(allocated)
    assert manager.blocks[MappedBlock] == [occupied, allocated]
    assert allocated.file_addr == 0x110
    assert allocated.mem_addr == 0x1010
    assert allocated.size == 0x20
    assert allocated.is_free


def test_failed_aligned_allocation_does_not_advance_open_end():
    image = FakeImageBackend()
    manager = make_manager(image)
    file_block = FileBlock(addr=0x2003, size=-1)
    memory_block = MemoryBlock(addr=0x3000, size=-1)
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
    image = FakeImageBackend()
    manager = make_manager(image, ElfBareMetalAllocationExtender())
    manager.add_block(FileBlock(addr=0x1000, size=-1))
    manager.add_block(FlashBlock(addr=0x2000, size=0x10000))
    manager.add_block(RamBlock(addr=0x4000, size=0x10000))

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
    assert restored.size == 0x20


def test_custom_allocator_rejects_allocation_outside_finite_flash_ranges():
    image = FakeImageBackend()
    manager = make_manager(image, ElfBareMetalAllocationExtender())
    file_block = FileBlock(addr=0x1000, size=-1)
    flash_block = FlashBlock(addr=0x2000, size=0x10000)
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
    image = FakeImageBackend()
    manager = make_manager(image, ElfBareMetalAllocationExtender())
    file_block = FileBlock(addr=0x1000, size=-1)
    flash_block = FlashBlock(addr=0x2000, size=0x20000)
    manager.add_block(file_block)
    manager.add_block(flash_block)

    block = manager.allocate(
        AllocationManager.CHUNK + 1,
        flag=MemoryFlag.RX,
    )

    assert block.size == AllocationManager.CHUNK + 1
    assert manager.new_mapped_blocks[0].size == block.size
    assert file_block.addr == 0x1000 + block.size
    assert flash_block not in manager.blocks[FlashBlock]
    remaining_flash = manager.blocks[FlashBlock][0]
    assert remaining_flash.addr == 0x2000 + block.size
    assert remaining_flash.addr + remaining_flash.size == 0x22000


def test_finalize_trims_extents_across_coalesced_free_blocks():
    image = FakeImageBackend()
    manager = make_manager(image)
    manager.add_block(FileBlock(addr=0, size=-1))
    manager.add_block(MemoryBlock(addr=0, size=-1))

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
    assert image.file_size == 0x11010
