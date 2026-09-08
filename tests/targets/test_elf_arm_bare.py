from typing import cast

import pytest
from elftools.construct.lib.container import Container
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from pydantic import ValidationError

from patcherex2.components.allocation_manager import (
    AllocationManager,
    FileBlock,
    MemoryFlag,
)
from patcherex2.components.image.bare_elf import BareMetalElfImageBackend
from patcherex2.components.load_models import ArmBareMetalLoadModel
from patcherex2.components.placement_strategies import (
    BareMetalAddressSpace,
    ElfBareMetalAllocationExtender,
    ElfExplicitPlacement,
    FlashBlock,
    RamBlock,
)
from patcherex2.session import PatchSession
from patcherex2.targets import (
    ARM_ELF_BARE,
    ArmBareMetalRuntimeConfig,
    ComponentOverrides,
    TargetConfig,
)
from tests.support.fakes import FakeBinaryAnalyzer, FakeImageBackend, FakeLoadModelContext
from tests.support.paths import TEST_BINARIES


def segment(
    *,
    vaddr: int,
    paddr: int,
    filesz: int,
    memsz: int,
    offset: int = 0,
) -> Container:
    return Container(
        p_type="PT_LOAD",
        p_offset=offset,
        p_vaddr=vaddr,
        p_paddr=paddr,
        p_filesz=filesz,
        p_memsz=memsz,
    )


def analyze_memory(
    segments: list[Container],
    unused_flash: list[range],
    unused_ram: list[range],
):
    image = BareMetalElfImageBackend(str(TEST_BINARIES / "armhf/printf_nopie"))
    manager = AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=image,
        extender=ElfBareMetalAllocationExtender(),
    )
    image._segments = segments
    image.file_size = 0
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=tuple(unused_flash),
            unused_ram=tuple(unused_ram),
        )
    ).initialize(
        image=image,
        allocation_manager=manager,
    )
    return image, manager


def test_explicit_discontiguous_ranges_become_finite_allocation_blocks():
    _, manager = analyze_memory(
        [segment(vaddr=0, paddr=0, filesz=0x100, memsz=0x100)],
        [range(0x100, 0x200), range(0x300, 0x500)],
        [range(0x20000000, 0x20000100)],
    )

    assert [(block.addr, block.size) for block in manager.blocks[FlashBlock]] == [
        (0x100, 0x100),
        (0x300, 0x200),
    ]
    assert [(block.addr, block.size) for block in manager.blocks[RamBlock]] == [(0x20000000, 0x100)]


def test_address_space_normalizes_ranges():
    address_space = BareMetalAddressSpace(
        unused_flash=(range(0x300, 0x400), range(0x100, 0x200)),
        unused_ram=(),
    )

    assert address_space.unused_flash == (
        range(0x100, 0x200),
        range(0x300, 0x400),
    )


def test_elf_zero_alignment_is_treated_as_no_alignment_requirement():
    image = BareMetalElfImageBackend(str(TEST_BINARIES / "armhf/printf_nopie"))
    for item in image._segments:
        item["p_align"] = 0
    assert image.page_alignment() == 1


@pytest.mark.parametrize("field", ["unused_flash", "unused_ram"])
def test_address_space_rejects_negative_addresses(field):
    with pytest.raises(ValidationError, match="non-negative"):
        BareMetalAddressSpace(
            **{
                field: (range(-1, 8),),
                "unused_ram" if field == "unused_flash" else "unused_flash": (),
            }
        )


def test_address_space_rejects_overlapping_ranges():
    with pytest.raises(ValidationError, match="ranges overlap"):
        BareMetalAddressSpace(
            unused_flash=(range(0x100, 0x300), range(0x200, 0x400)),
            unused_ram=(),
        )


def test_elf_load_image_overlap_is_validated_with_paddr_and_filesz():
    segments = [
        segment(
            vaddr=0x20000000,
            paddr=0x1000,
            filesz=0x20,
            memsz=0x120,
        )
    ]

    with pytest.raises(ValueError, match="unused_flash.*occupied image range"):
        analyze_memory(
            segments,
            [range(0x1010, 0x1030)],
            [range(0x20000200, 0x20000300)],
        )

    analyze_memory(
        segments,
        [range(0x1020, 0x1100)],
        [range(0x20000120, 0x20000200)],
    )


def test_runtime_overlap_is_validated_with_vaddr_and_memsz():
    segments = [
        segment(
            vaddr=0x20000000,
            paddr=0x1000,
            filesz=0x20,
            memsz=0x120,
        )
    ]

    with pytest.raises(ValueError, match="unused_ram.*occupied image range"):
        analyze_memory(
            segments,
            [range(0x1020, 0x1100)],
            [range(0x20000100, 0x20000200)],
        )


def test_allocator_uses_later_flash_range_when_first_is_too_small():
    image = FakeImageBackend(alignment=0x100)
    manager = AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=image,
        extender=ElfBareMetalAllocationExtender(),
    )
    manager.add_block(FileBlock(addr=0x10000, size=-1))
    manager.add_block(FlashBlock(addr=0x100, size=0x10))
    manager.add_block(FlashBlock(addr=0x300, size=0x200))

    block = manager.allocate(0x20, flag=MemoryFlag.RX)

    assert block.mem_addr == 0x300
    assert block.load_mem_addr == 0x300
    assert block.file_addr == 0x10000
    assert block.mem_addr + block.size <= 0x500


def test_allocator_searches_within_a_finite_range_for_valid_address():
    image = FakeImageBackend(alignment=0x100)
    manager = AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=image,
        extender=ElfBareMetalAllocationExtender(),
    )
    manager.add_block(FileBlock(addr=0x10000, size=-1))
    manager.add_block(FlashBlock(addr=0x300, size=0x200))

    block = manager.allocate(
        4,
        flag=MemoryFlag.RX,
        align=4,
        address_validator=lambda address: address == 0x380,
    )

    assert block.mem_addr == 0x380
    assert block.load_mem_addr == 0x380


def test_allocator_fails_when_no_finite_flash_range_can_fit_request():
    image = FakeImageBackend(alignment=0x100)
    manager = AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=image,
        extender=ElfBareMetalAllocationExtender(),
    )
    file_block = FileBlock(addr=0x10000, size=-1)
    manager.add_block(file_block)
    manager.add_block(FlashBlock(addr=0x100, size=0x10))
    manager.add_block(FlashBlock(addr=0x300, size=0x1F))

    with pytest.raises(MemoryError, match="Insufficient memory"):
        manager.allocate(0x20, flag=MemoryFlag.RX)

    assert file_block.addr == 0x10000
    assert manager.new_mapped_blocks == []


def test_finalize_emits_elf_load_segment_for_authorized_flash(tmp_path):
    input_path = str(TEST_BINARIES / "armhf/printf_nopie")
    analyzer = FakeBinaryAnalyzer()
    elf = BareMetalElfImageBackend(input_path)
    manager = AllocationManager(
        binary_analyzer=analyzer,
        image=elf,
        extender=ElfBareMetalAllocationExtender(),
    )
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=(range(0x30000000, 0x30020000),),
            unused_ram=(),
        )
    ).initialize(image=elf, allocation_manager=manager)
    block = manager.allocate(4, flag=MemoryFlag.RX, align=4)
    elf.update_binary_content(block.file_addr, b"TEST")

    elf.finalize(manager, analyzer)
    output_path = tmp_path / "patched.elf"
    elf.save_binary(output_path)

    with output_path.open("rb") as file_handle:
        patched = ELFFile(file_handle)
        matching = [
            item
            for item in patched.iter_segments()
            if item["p_type"] == "PT_LOAD" and item["p_paddr"] == block.load_mem_addr
        ]
        assert len(matching) == 1
        assert matching[0]["p_vaddr"] == block.mem_addr
        assert matching[0]["p_filesz"] == 4
        file_handle.seek(matching[0]["p_offset"])
        assert file_handle.read(4) == b"TEST"


@pytest.mark.parametrize(
    ("memory_flag", "unused_ram", "expected_section_flags"),
    [
        (MemoryFlag.RX, (), SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR),
        (
            MemoryFlag.RW,
            (range(0x40000000, 0x40020000),),
            SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE,
        ),
    ],
)
def test_finalize_emits_section_flags_matching_memory_permissions(
    tmp_path,
    memory_flag,
    unused_ram,
    expected_section_flags,
):
    input_path = str(TEST_BINARIES / "armhf/printf_nopie")
    analyzer = FakeBinaryAnalyzer()
    elf = BareMetalElfImageBackend(input_path)
    manager = AllocationManager(
        binary_analyzer=analyzer,
        image=elf,
        extender=ElfBareMetalAllocationExtender(),
    )
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=(range(0x30000000, 0x30020000),),
            unused_ram=unused_ram,
        )
    ).initialize(image=elf, allocation_manager=manager)
    block = manager.allocate(4, flag=memory_flag, align=4)
    elf.update_binary_content(block.file_addr, b"TEST")

    elf.finalize(manager, analyzer)
    output_path = tmp_path / "patched.elf"
    elf.save_binary(output_path)

    with output_path.open("rb") as file_handle:
        patched = ELFFile(file_handle)
        matching = [
            section
            for section in patched.iter_sections()
            if section["sh_offset"] == block.file_addr
            and section["sh_addr"] == block.mem_addr
            and section["sh_size"] == block.size
        ]

    assert len(matching) == 1
    assert matching[0]["sh_flags"] == expected_section_flags


def test_finalize_removes_pt_phdr_when_program_headers_are_relocated(tmp_path):
    input_path = str(TEST_BINARIES / "armhf/printf_nopie")
    analyzer = FakeBinaryAnalyzer()
    elf = BareMetalElfImageBackend(input_path)
    original_program_header_offset = elf._elf.header["e_phoff"]
    manager = AllocationManager(
        binary_analyzer=analyzer,
        image=elf,
        extender=ElfBareMetalAllocationExtender(),
    )
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=(range(0x30000000, 0x30020000),),
            unused_ram=(),
        )
    ).initialize(image=elf, allocation_manager=manager)
    block = manager.allocate(4, flag=MemoryFlag.RX, align=4)
    elf.update_binary_content(block.file_addr, b"TEST")

    elf.finalize(manager, analyzer)
    output_path = tmp_path / "patched.elf"
    elf.save_binary(output_path)

    with output_path.open("rb") as file_handle:
        patched = ELFFile(file_handle)
        assert patched.header["e_phoff"] != original_program_header_offset
        assert all(segment["p_type"] != "PT_PHDR" for segment in patched.iter_segments())


def test_finalize_emits_program_headers_in_elf_order(tmp_path):
    input_path = str(TEST_BINARIES / "armhf/printf_nopie")
    analyzer = FakeBinaryAnalyzer()
    elf = BareMetalElfImageBackend(input_path)
    manager = AllocationManager(
        binary_analyzer=analyzer,
        image=elf,
        extender=ElfBareMetalAllocationExtender(),
    )
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=(range(0x30000000, 0x30020000),),
            unused_ram=(),
        )
    ).initialize(image=elf, allocation_manager=manager)
    block = manager.allocate(4, flag=MemoryFlag.RX, align=4)
    elf.update_binary_content(block.file_addr, b"TEST")

    elf.finalize(manager, analyzer)
    output_path = tmp_path / "patched.elf"
    elf.save_binary(output_path)

    with output_path.open("rb") as file_handle:
        patched = ELFFile(file_handle)
        segments = list(patched.iter_segments())

    segment_types = [segment["p_type"] for segment in segments]
    interpreter_index = segment_types.index("PT_INTERP")
    load_indices = [
        index for index, segment_type in enumerate(segment_types) if segment_type == "PT_LOAD"
    ]
    load_addresses = [segment["p_vaddr"] for segment in segments if segment["p_type"] == "PT_LOAD"]

    assert interpreter_index < min(load_indices)
    assert load_addresses == sorted(load_addresses)


def test_elf_segments_with_discontiguous_load_addresses_are_not_merged():
    previous = Container(
        p_type="PT_LOAD",
        p_offset=0x1000,
        p_filesz=0x100,
        p_vaddr=0x20000000,
        p_paddr=0x08000000,
        p_memsz=0x100,
        p_flags=MemoryFlag.RW,
        p_align=0x1000,
    )
    following = Container(
        p_type="PT_LOAD",
        p_offset=0x1100,
        p_filesz=0x100,
        p_vaddr=0x20000100,
        p_paddr=0x08001000,
        p_memsz=0x100,
        p_flags=MemoryFlag.RW,
        p_align=0x1000,
    )

    merged = BareMetalElfImageBackend._merge_adjacent_load_segments([previous, following])

    assert merged == [previous, following]


def test_segment_merge_preserves_a_zero_filled_tail():
    previous = Container(
        p_type="PT_LOAD",
        p_offset=0x1000,
        p_filesz=0x80,
        p_memsz=0x100,
        p_vaddr=0x2000,
        p_paddr=0x8000,
        p_flags=MemoryFlag.RW,
        p_align=1,
    )
    following = Container(
        p_type="PT_LOAD",
        p_offset=0x1080,
        p_filesz=0x40,
        p_memsz=0x40,
        p_vaddr=0x2100,
        p_paddr=0x8080,
        p_flags=MemoryFlag.RW,
        p_align=1,
    )
    assert BareMetalElfImageBackend._merge_adjacent_load_segments([previous, following]) == [
        previous,
        following,
    ]


def test_elf_writable_allocation_requires_an_insert_point():
    elf = BareMetalElfImageBackend(str(TEST_BINARIES / "armhf/printf_nopie"))
    manager = AllocationManager(
        binary_analyzer=FakeBinaryAnalyzer(),
        image=elf,
        extender=ElfBareMetalAllocationExtender(),
    )
    ElfExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=(range(0x30000000, 0x30020000),),
            unused_ram=(range(0x40000000, 0x40020000),),
        )
    ).initialize(image=elf, allocation_manager=manager)
    manager.allocate(4, flag=MemoryFlag.RW, align=4)

    with pytest.raises(RuntimeError, match="needs at least one insert point"):
        ArmBareMetalLoadModel([]).prepare(cast(PatchSession, FakeLoadModelContext(manager)))


def test_elf_arm_target_composes_architecture_image_load_and_placement_layers():
    with PatchSession.load_binary(
        TEST_BINARIES / "armhf/printf_nopie",
        target=ARM_ELF_BARE,
        config=TargetConfig(
            overrides=ComponentOverrides(
                placement=ElfExplicitPlacement(
                    BareMetalAddressSpace(
                        unused_flash=(range(0x30000000, 0x30020000),),
                        unused_ram=(),
                    )
                ),
                load_model=ArmBareMetalRuntimeConfig().build(),
            )
        ),
    ) as patcher:
        assert patcher.target is ARM_ELF_BARE
        assert isinstance(patcher.image, BareMetalElfImageBackend)
        assert isinstance(patcher.placement_strategy, ElfExplicitPlacement)
        assert isinstance(patcher.load_model, ArmBareMetalLoadModel)


def test_elf_arm_target_requires_explicit_placement():
    placement_factory = ARM_ELF_BARE.image.placement
    assert placement_factory is not None

    with pytest.raises(ValueError, match="require an ElfExplicitPlacement override"):
        placement_factory.select(None)()
