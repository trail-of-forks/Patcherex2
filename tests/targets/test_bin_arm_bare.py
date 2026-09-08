from typing import cast

import pytest
from pydantic import ValidationError

from patcherex2.components.allocation_manager import (
    AllocationManager,
    MappedBlock,
    MemoryFlag,
)
from patcherex2.components.load_models import ArmBareMetalLoadModel
from patcherex2.components.placement_strategies import (
    BareMetalAddressSpace,
    FlashBlock,
    RamBlock,
    RawBareMetalAllocationExtender,
    RawExplicitPlacement,
)
from patcherex2.patch.instruction import InsertInstructionPatch
from patcherex2.session import PatchSession
from patcherex2.targets import (
    ARM_RAW_BARE,
    ArmBareMetalRuntimeConfig,
    ArmRawImageConfig,
    ComponentOverrides,
    TargetConfig,
)
from patcherex2.targets.bin_arm_bare import ArmRawImageBackend
from tests.support.fakes import FakeAllocator, FakeBinaryAnalyzer, FakeLoadModelContext


def configured_binary(
    tmp_path,
    *,
    image_base: int = 0x1000,
    fill_byte: int = 0xFF,
    unused_flash: list[range] | None = None,
    unused_ram: list[range] | None = None,
):
    input_path = tmp_path / "firmware.bin"
    input_path.write_bytes(b"\xaa\xbb")
    analyzer = FakeBinaryAnalyzer()
    unused_flash = unused_flash or [range(0x1002, 0x1100)]
    unused_ram = unused_ram or [range(0x2000, 0x2100)]
    binary = ArmRawImageBackend(input_path, image_base=image_base, fill_byte=fill_byte)
    manager = AllocationManager(
        binary_analyzer=analyzer,
        image=binary,
        extender=RawBareMetalAllocationExtender(),
    )
    RawExplicitPlacement(
        BareMetalAddressSpace(
            unused_flash=tuple(unused_flash),
            unused_ram=tuple(unused_ram),
        )
    ).initialize(
        image=binary,
        allocation_manager=manager,
    )
    return binary, manager, analyzer


def test_raw_flash_address_maps_to_offset_from_image_base(tmp_path):
    _, manager, analyzer = configured_binary(tmp_path)

    block = manager.allocate(4, flag=MemoryFlag.RX, align=2)

    assert block.file_addr == 2
    assert block.mem_addr == 0x1002
    assert block.load_mem_addr == 0x1002
    assert analyzer is manager.binary_analyzer


def test_raw_allocations_reuse_the_remainder_of_a_small_range(tmp_path):
    _, manager, _ = configured_binary(tmp_path)

    first = manager.allocate(4, flag=MemoryFlag.RX, align=2)
    second = manager.allocate(4, flag=MemoryFlag.RX, align=2)

    assert first.load_mem_addr == 0x1002
    assert second.load_mem_addr == 0x1006


def test_raw_writable_allocation_pairs_flash_storage_with_ram(tmp_path):
    _, manager, _ = configured_binary(tmp_path)

    block = manager.allocate(4, flag=MemoryFlag.RW, align=4)

    assert block.file_addr == 2
    assert block.load_mem_addr == 0x1002
    assert block.mem_addr == 0x2000


def test_raw_writable_allocation_requires_an_insert_point(tmp_path):
    _binary, manager, _ = configured_binary(tmp_path)
    manager.allocate(4, flag=MemoryFlag.RW)

    with pytest.raises(RuntimeError, match="needs at least one insert point"):
        ArmBareMetalLoadModel([]).prepare(cast(PatchSession, FakeLoadModelContext(manager)))


def test_load_model_does_nothing_without_initialized_ram():
    patcher = cast(PatchSession, FakeLoadModelContext(FakeAllocator()))

    ArmBareMetalLoadModel([0x1000]).prepare(patcher)


def record_load_model_patches(monkeypatch: pytest.MonkeyPatch):
    inserted = []

    def record_patch(patch, patcher):
        inserted.append((patch.addr, patch.instr, patch.save_context, patcher))

    monkeypatch.setattr(InsertInstructionPatch, "apply", record_patch)
    allocation_manager = FakeAllocator()
    allocation_manager.new_mapped_blocks = [
        MappedBlock(
            file_addr=0,
            addr=0x2000,
            size=4,
            flag=MemoryFlag.RW,
            load_mem_addr=0x1000,
        ),
    ]
    patcher = cast(PatchSession, FakeLoadModelContext(allocation_manager))

    ArmBareMetalLoadModel([0x80, 0x100]).prepare(patcher)

    return inserted


def test_arm_load_model_applies_initialization_at_every_insert_point(monkeypatch):
    inserted = record_load_model_patches(monkeypatch)

    assert [item[0] for item in inserted] == [0x80, 0x100]


def test_arm_load_model_copies_from_flash_to_runtime_ram(monkeypatch):
    inserted = record_load_model_patches(monkeypatch)

    assert all("ldr r0, =0x1000" in item[1] for item in inserted)
    assert all("ldr r1, =0x2000" in item[1] for item in inserted)


def test_arm_load_model_preserves_context_around_initialization(monkeypatch):
    inserted = record_load_model_patches(monkeypatch)

    assert all(item[2] is True for item in inserted)


def test_raw_save_uses_configured_fill_byte_for_image_extension(tmp_path):
    binary, _, _ = configured_binary(tmp_path, fill_byte=0xEE)
    output_path = tmp_path / "patched.bin"
    binary.update_binary_content(4, b"\xcc")

    binary.save_binary(output_path)

    assert output_path.read_bytes() == b"\xaa\xbb\xee\xee\xcc"


def test_raw_flash_ranges_cannot_precede_image_base(tmp_path):
    with pytest.raises(ValueError, match="below image_base"):
        configured_binary(tmp_path, unused_flash=[range(0xFFF, 0x1100)])


@pytest.mark.parametrize(
    ("options", "field"),
    [
        ({"image_base": -1}, "image_base"),
        ({"image_base": 0, "fill_byte": 0x100}, "fill_byte"),
    ],
)
def test_raw_image_config_rejects_invalid_values(options, field):
    with pytest.raises(ValidationError, match=field):
        ArmRawImageConfig(**options)


def test_runtime_config_validates_insert_points():
    with pytest.raises(ValidationError, match="insert_points"):
        ArmBareMetalRuntimeConfig(insert_points=(-1,))


def test_raw_ranges_are_finite(tmp_path):
    _, manager, _ = configured_binary(tmp_path)

    assert [(block.addr, block.size) for block in manager.blocks[FlashBlock]] == [(0x1002, 0xFE)]
    assert [(block.addr, block.size) for block in manager.blocks[RamBlock]] == [(0x2000, 0x100)]


def test_bin_arm_target_composes_architecture_image_load_and_placement_layers(
    tmp_path,
):
    input_path = tmp_path / "firmware.bin"
    input_path.write_bytes(b"\xaa\xbb")

    with PatchSession.load_binary(
        input_path,
        target=ARM_RAW_BARE,
        config=TargetConfig(
            overrides=ComponentOverrides(
                image=ArmRawImageConfig(image_base=0x1000).build,
                placement=RawExplicitPlacement(
                    BareMetalAddressSpace(
                        unused_flash=(range(0x1002, 0x1100),),
                        unused_ram=(),
                    )
                ),
                load_model=ArmBareMetalRuntimeConfig().build(),
            )
        ),
    ) as patcher:
        assert patcher.target is ARM_RAW_BARE
        assert isinstance(patcher.image, ArmRawImageBackend)
        assert patcher.binary_analyzer.load_base == 0x1000
        assert isinstance(patcher.placement_strategy, RawExplicitPlacement)
        assert isinstance(patcher.load_model, ArmBareMetalLoadModel)
