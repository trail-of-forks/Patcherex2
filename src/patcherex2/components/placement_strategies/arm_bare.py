from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import TYPE_CHECKING, Annotated, Protocol, cast, final

from pydantic import BeforeValidator

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.allocation_manager import (
    AllocationExtender,
    AllocationManager,
    AllocationRequest,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from patcherex2.components.placement_strategies.placement_strategy import (
    PlacementStrategy,
)
from patcherex2.models import FrozenPatcherexModel

if TYPE_CHECKING:
    from patcherex2.components.image import ImageBackend


class ElfPlacementImage(Protocol):
    def occupied_load_ranges(self) -> list[range]: ...

    def occupied_runtime_ranges(self) -> list[range]: ...

    def next_file_offset(self) -> int: ...


class RawPlacementImage(Protocol):
    image_base: int


def _normalize_flash_ranges(ranges: Iterable[range]) -> tuple[range, ...]:
    return tuple(_normalize_ranges("unused_flash", ranges))


def _normalize_ram_ranges(ranges: Iterable[range]) -> tuple[range, ...]:
    return tuple(_normalize_ranges("unused_ram", ranges))


MemoryRanges = tuple[range, ...]
UnusedFlashRanges = Annotated[MemoryRanges, BeforeValidator(_normalize_flash_ranges)]
UnusedRamRanges = Annotated[MemoryRanges, BeforeValidator(_normalize_ram_ranges)]


class BareMetalAddressSpace(FrozenPatcherexModel):
    """Caller-authorized, half-open bare-metal memory ranges."""

    unused_flash: UnusedFlashRanges
    unused_ram: UnusedRamRanges


class FlashBlock(MemoryBlock):
    pass


class RamBlock(MemoryBlock):
    pass


@final
class ElfBareMetalAllocationExtender(AllocationExtender):
    """Extend allocations into caller-authorized ELF flash and RAM ranges."""

    mapped_block_granularity = 0

    @override
    def extend(self, manager: AllocationManager, request: AllocationRequest) -> bool:
        file_block = next(
            (block for block in manager.blocks[FileBlock] if block.size == -1),
            None,
        )
        if file_block is None:
            return False
        placement = self._find_placement(
            manager,
            file_block.addr,
            manager.image.page_alignment(),
            request,
        )
        if placement is None:
            return False
        flash_block, ram_block, load_addr, mem_addr, block_size = placement
        file_addr = file_block.addr
        file_block.addr += block_size
        _consume_region(manager, flash_block, load_addr, block_size)
        if ram_block is not None:
            _consume_region(manager, ram_block, mem_addr, block_size)
        manager._add_new_mapped_block(
            MappedBlock(
                file_addr=file_addr,
                addr=mem_addr,
                size=block_size,
                flag=request.flag,
                load_mem_addr=load_addr,
            )
        )
        return True

    def _find_placement(
        self,
        manager: AllocationManager,
        file_addr: int,
        page_align: int,
        request: AllocationRequest,
    ) -> tuple[FlashBlock, RamBlock | None, int, int, int] | None:
        _validate_flags(request.flag)
        ram_blocks = manager.blocks[RamBlock] if request.flag == MemoryFlag.RW else [None]
        for flash_block in manager.blocks[FlashBlock]:
            load_addr = flash_block.addr + (file_addr - flash_block.addr) % page_align
            flash_available = flash_block.addr + flash_block.size - load_addr
            for ram_block in ram_blocks:
                mem_addr, available = _runtime_candidate(
                    ram_block,
                    file_addr,
                    page_align,
                    load_addr,
                    flash_available,
                )
                block_size = _prospective_size(
                    manager,
                    request,
                    mem_addr,
                    available,
                )
                if block_size is not None:
                    return flash_block, ram_block, load_addr, mem_addr, block_size
        return None


@final
class RawBareMetalAllocationExtender(AllocationExtender):
    """Extend allocations into caller-authorized raw-image flash and RAM."""

    mapped_block_granularity = 0

    @override
    def extend(self, manager: AllocationManager, request: AllocationRequest) -> bool:
        _validate_flags(request.flag)
        ram_blocks = manager.blocks[RamBlock] if request.flag == MemoryFlag.RW else [None]
        for flash_block in manager.blocks[FlashBlock]:
            for ram_block in ram_blocks:
                mem_addr = flash_block.addr if ram_block is None else ram_block.addr
                available = flash_block.size
                if ram_block is not None:
                    available = min(available, ram_block.size)
                block_size = _prospective_size(
                    manager,
                    request,
                    mem_addr,
                    available,
                )
                if block_size is None:
                    continue
                self._commit_placement(
                    manager,
                    flash_block,
                    ram_block,
                    mem_addr,
                    block_size,
                    request.flag,
                )
                return True
        return False

    def _commit_placement(
        self,
        manager: AllocationManager,
        flash_block: FlashBlock,
        ram_block: RamBlock | None,
        mem_addr: int,
        block_size: int,
        flag: MemoryFlag,
    ) -> None:
        load_addr = flash_block.addr
        image = cast(RawPlacementImage, manager.image)
        file_addr = load_addr - image.image_base
        _consume_region(manager, flash_block, load_addr, block_size)
        if ram_block is not None:
            _consume_region(manager, ram_block, mem_addr, block_size)
        manager._add_new_mapped_block(
            MappedBlock(
                file_addr=file_addr,
                addr=mem_addr,
                size=block_size,
                flag=flag,
                load_mem_addr=load_addr,
            )
        )


class ElfExplicitPlacement(PlacementStrategy):
    def __init__(self, address_space: BareMetalAddressSpace):
        self.address_space = address_space

    @override
    def initialize(
        self,
        *,
        image: ImageBackend,
        allocation_manager: AllocationManager,
    ) -> None:
        elf_image = cast(ElfPlacementImage, image)
        _reject_overlaps(
            "unused_flash",
            self.address_space.unused_flash,
            elf_image.occupied_load_ranges(),
        )
        _reject_overlaps(
            "unused_ram",
            self.address_space.unused_ram,
            elf_image.occupied_runtime_ranges(),
        )
        allocation_manager.add_block(FileBlock(addr=elf_image.next_file_offset(), size=-1))
        _add_regions(
            allocation_manager,
            FlashBlock,
            self.address_space.unused_flash,
        )
        _add_regions(
            allocation_manager,
            RamBlock,
            self.address_space.unused_ram,
        )


class RawExplicitPlacement(PlacementStrategy):
    def __init__(self, address_space: BareMetalAddressSpace):
        self.address_space = address_space

    @override
    def initialize(
        self,
        *,
        image: ImageBackend,
        allocation_manager: AllocationManager,
    ) -> None:
        image_base = cast(RawPlacementImage, image).image_base
        if any(item.start < image_base for item in self.address_space.unused_flash):
            raise ValueError("unused_flash cannot begin below image_base")
        _add_regions(
            allocation_manager,
            FlashBlock,
            self.address_space.unused_flash,
        )
        _add_regions(
            allocation_manager,
            RamBlock,
            self.address_space.unused_ram,
        )


def _normalize_ranges(name: str, ranges: Iterable[range]) -> list[range]:
    normalized = list(ranges)
    for current in normalized:
        if not isinstance(current, range):
            raise TypeError(f"{name} entries must be ranges, got {type(current).__name__}")
    normalized.sort(key=lambda item: (item.start, item.stop))
    previous = None
    for current in normalized:
        if current.start < 0:
            raise ValueError(f"{name} ranges must have non-negative addresses: {current!r}")
        if current.step != 1:
            raise ValueError(f"{name} ranges must have a step of 1: {current!r}")
        if current.start >= current.stop:
            raise ValueError(f"{name} ranges must be non-empty: {current!r}")
        if previous is not None and current.start < previous.stop:
            raise ValueError(f"{name} ranges overlap: {previous!r} and {current!r}")
        previous = current
    return normalized


def _validate_flags(flag: MemoryFlag) -> None:
    if flag not in (MemoryFlag.RW, MemoryFlag.RX):
        raise NotImplementedError(f"Unsupported memory flags: {flag!r}")


def _runtime_candidate(
    ram_block: RamBlock | None,
    file_addr: int,
    page_align: int,
    load_addr: int,
    flash_available: int,
) -> tuple[int, int]:
    if ram_block is None:
        return load_addr, flash_available
    mem_addr = ram_block.addr + (file_addr - ram_block.addr) % page_align
    ram_available = ram_block.addr + ram_block.size - mem_addr
    return mem_addr, min(flash_available, ram_available)


def _prospective_size(
    manager: AllocationManager,
    request: AllocationRequest,
    mem_addr: int,
    available: int,
) -> int | None:
    if available <= 0:
        return None
    return manager._prospective_open_end_size(
        mem_addr,
        request,
        max_block_size=available,
    )


def _consume_region(
    manager: AllocationManager,
    block: MemoryBlock,
    start: int,
    size: int,
) -> None:
    block_type = type(block)
    block_end = block.addr + block.size
    manager.blocks[block_type].remove(block)
    if block.addr < start:
        manager.add_block(block_type(addr=block.addr, size=start - block.addr))
    used_end = start + size
    if used_end < block_end:
        manager.add_block(block_type(addr=used_end, size=block_end - used_end))


def _add_regions(
    manager: AllocationManager,
    block_type: type[MemoryBlock],
    ranges: Iterable[range],
) -> None:
    for memory_range in ranges:
        manager.add_block(
            block_type(
                addr=memory_range.start,
                size=memory_range.stop - memory_range.start,
            )
        )


def _reject_overlaps(
    name: str,
    unused: Iterable[range],
    occupied: Iterable[range],
) -> None:
    for free_range in unused:
        for occupied_range in occupied:
            if free_range.start < occupied_range.stop and occupied_range.start < free_range.stop:
                raise ValueError(
                    f"{name} range {free_range!r} overlaps occupied image range {occupied_range!r}"
                )
