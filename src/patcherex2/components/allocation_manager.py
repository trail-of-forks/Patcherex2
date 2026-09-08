from __future__ import annotations

import enum
import logging
import sys
from collections.abc import Callable, Iterator, Mapping, ValuesView
from pprint import pformat
from typing import TYPE_CHECKING, Annotated, Protocol, TypeVar, cast, final, runtime_checkable

from pydantic import AfterValidator, ConfigDict, Field, model_validator

from patcherex2.models import FrozenPatcherexModel, PatcherexModel

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

if TYPE_CHECKING:
    from patcherex2.components.binary_analyzer import BinaryAnalyzer
    from patcherex2.components.image import ImageBackend

logger = logging.getLogger(__name__)


def _reject_zero_extent(value: int) -> int:
    if value == 0:
        raise ValueError("block size cannot be zero")
    return value


ExtentSize = Annotated[int, Field(ge=-1), AfterValidator(_reject_zero_extent)]


class Block(PatcherexModel):
    """A contiguous file or memory extent tracked by the allocator."""

    model_config = ConfigDict(validate_assignment=True)

    addr: Annotated[int, Field(ge=0)]
    size: ExtentSize
    is_free: bool = True

    def __lt__(self, other: Block) -> bool:
        return self.addr < other.addr

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} addr={hex(self.addr)} size={hex(self.size)} is_free={self.is_free}>"

    def coalesce(self, other: Block) -> bool:
        if self.is_free and other.is_free and self.addr + self.size == other.addr:
            self.size += other.size
            return True
        return False


class FileBlock(Block):
    """An extent in the input or output file."""


class MemoryBlock(Block):
    """An extent in the runtime address space."""


class MemoryFlag(enum.IntFlag):
    UNDEF = 0
    R = 0x4
    W = 0x2
    X = 0x1
    RW = R | W
    RX = R | X
    RWX = R | W | X

    @classmethod
    def parse(cls, value: str | MemoryFlag) -> MemoryFlag:
        """Normalize a memory flag or a string such as ``"RX"``."""
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise TypeError(f"Memory flag must be str or MemoryFlag, got {type(value).__name__}")
        characters = set(value.lower())
        if not characters or characters - {"r", "w", "x"}:
            raise ValueError(f"Invalid memory flag {value!r}: expected a subset of 'r', 'w', 'x'")
        result = cls(0)
        if "r" in characters:
            result |= cls.R
        if "w" in characters:
            result |= cls.W
        if "x" in characters:
            result |= cls.X
        return result


class MappedBlock(Block):
    """An extent with corresponding file, load, and runtime addresses."""

    file_addr: Annotated[int, Field(ge=0)]
    flag: MemoryFlag = MemoryFlag.RWX
    load_mem_addr: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="before")
    @classmethod
    def default_load_address(cls, data: object) -> object:
        if not isinstance(data, Mapping):
            return data
        values = dict(data)
        if values.get("load_mem_addr") is None and "addr" in values:
            values["load_mem_addr"] = values["addr"]
        return values

    @property
    def mem_addr(self) -> int:
        """The mapped runtime address, stored canonically as :attr:`addr`."""
        return self.addr

    @mem_addr.setter
    def mem_addr(self, value: int) -> None:
        self.addr = value

    @override
    def __repr__(self) -> str:
        r = (
            f"<{self.__class__.__name__} file_addr={hex(self.file_addr)} "
            f"mem_addr={hex(self.mem_addr)} size={hex(self.size)} "
            f"is_free={self.is_free} flag={self.flag}"
        )
        if self.load_mem_addr != self.mem_addr:
            r += f" load_mem_addr={hex(self.load_mem_addr)}"
        return r + ">"

    def coalesce(self, other: Block) -> bool:
        if not isinstance(other, MappedBlock):
            return False
        if (
            self.is_free
            and other.is_free
            and self.flag == other.flag
            and self.file_addr + self.size == other.file_addr
            and self.mem_addr + self.size == other.mem_addr
            and self.load_mem_addr + self.size == other.load_mem_addr
        ):
            self.size += other.size
            return True
        return False


@runtime_checkable
class Allocator(Protocol):
    """Allocation operations consumed by patch construction utilities."""

    new_mapped_blocks: list[MappedBlock]

    def allocate(
        self,
        size: int,
        *,
        flag: MemoryFlag = MemoryFlag.RWX,
        align: int = 1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> MappedBlock:
        """Allocate a mapped block satisfying the supplied constraints."""
        ...

    def free(self, block: Block) -> None:
        """Return an allocated block to the allocator."""
        ...


BlockT = TypeVar("BlockT", bound=Block)


@final
class BlockStore:
    """Typed collections of blocks, partitioned by their concrete type."""

    def __init__(self) -> None:
        self._blocks: dict[type[Block], list[Block]] = {}

    def __getitem__(self, block_type: type[BlockT]) -> list[BlockT]:
        blocks = self._blocks.setdefault(block_type, [])
        return cast(list[BlockT], blocks)

    def __setitem__(self, block_type: type[BlockT], blocks: list[BlockT]) -> None:
        self._blocks[block_type] = cast(list[Block], blocks)

    def values(self) -> ValuesView[list[Block]]:
        return self._blocks.values()


class AllocationRequest(FrozenPatcherexModel):
    """Constraints for one mapped-memory allocation."""

    size: Annotated[int, Field(gt=0)]
    flag: MemoryFlag = MemoryFlag.RWX
    align: Annotated[int, Field(gt=0)] = 1
    near_addr: Annotated[int, Field(ge=0)] | None = None
    max_dist: Annotated[int, Field(ge=0)] | None = None
    address_validator: Callable[[int], bool] | None = None


class _MappedCandidate(FrozenPatcherexModel):
    block: MappedBlock
    address: Annotated[int, Field(ge=0)]
    metric: Annotated[int, Field(ge=0)]


class AllocationExtender(Protocol):
    """Policy for adding mapped space when existing extents are exhausted."""

    mapped_block_granularity: int

    def extend(self, manager: AllocationManager, request: AllocationRequest) -> bool:
        """Add a free mapped extent capable of satisfying ``request``."""
        ...


@final
class ImageAllocationExtender(AllocationExtender):
    """Add mapped space using finite gaps or the image's open end."""

    mapped_block_granularity = 0x10000

    @override
    def extend(self, manager: AllocationManager, request: AllocationRequest) -> bool:
        page_align = manager.image.page_alignment()
        if request.near_addr is not None or request.address_validator is not None:
            placement = manager._reserve_in_memory_gap(request, page_align)
            if placement is not None:
                file_addr, mem_addr, block_size = placement
                manager._add_new_mapped_block(
                    MappedBlock(
                        file_addr=file_addr,
                        addr=mem_addr,
                        size=block_size,
                        flag=request.flag,
                    )
                )
                logger.debug(
                    f"new mapped block: file={hex(file_addr)} mem={hex(mem_addr)} size={hex(block_size)}"
                )
                return True
        return manager._extend_at_open_end(request, page_align)


@final
class AllocationManager:
    """Allocate mapped file and memory regions from registered free extents."""

    CHUNK = 0x10000

    def __init__(
        self,
        *,
        binary_analyzer: BinaryAnalyzer,
        image: ImageBackend,
        extender: AllocationExtender | None = None,
    ) -> None:
        self.blocks = BlockStore()
        self.binary_analyzer: BinaryAnalyzer = binary_analyzer
        self.image: ImageBackend = image
        self.extender: AllocationExtender = extender or ImageAllocationExtender()
        self.new_mapped_blocks: list[MappedBlock] = []

    def add_block(self, block: Block) -> None:
        self.blocks[type(block)].append(block)
        self.blocks[type(block)].sort()
        self.coalesce(self.blocks[type(block)])

    def _add_new_mapped_block(self, block: MappedBlock) -> None:
        self.add_block(block)
        # finalize() needs the original extent, not the object split by allocate().
        self.new_mapped_blocks.append(
            MappedBlock(
                file_addr=block.file_addr,
                addr=block.mem_addr,
                size=block.size,
                is_free=block.is_free,
                flag=block.flag,
                load_mem_addr=block.load_mem_addr,
            )
        )

    def add_free_space(self, addr: int, size: int, flag: str | MemoryFlag = "RX") -> None:
        """`flag` accepts a MemoryFlag or short str ("RX", "rw", "RWX"...)."""
        block = MappedBlock(
            file_addr=self.binary_analyzer.mem_addr_to_file_offset(addr),
            addr=addr,
            size=size,
            is_free=True,
            flag=MemoryFlag.parse(flag),
        )
        self.add_block(block)

    def _allocate_from_mapped_blocks(self, request: AllocationRequest) -> MappedBlock | None:
        candidate = self._select_mapped_candidate(request)
        if candidate is None:
            return None
        return self._claim_mapped_range(
            candidate.block,
            candidate.address,
            request.size,
        )

    def _select_mapped_candidate(self, request: AllocationRequest) -> _MappedCandidate | None:
        # near_addr ranks candidates; max_dist rejects distant ones.
        # address_validator applies constraints that distance cannot express.
        best: _MappedCandidate | None = None
        for block in self.blocks[MappedBlock]:
            if not (
                block.is_free
                and block.size >= request.size
                and block.flag & request.flag == request.flag
            ):
                continue
            # Inclusive aligned range that can hold the request.
            first = (
                block.mem_addr + (request.align - block.mem_addr % request.align) % request.align
            )
            last_limit = block.mem_addr + block.size - request.size
            last = last_limit - last_limit % request.align
            if first > last:
                continue

            # Without near_addr, scan upward from the first valid address.
            allocation_addr = self._first_valid_address(
                first,
                last,
                request,
            )
            if allocation_addr is None:
                continue
            metric = (
                block.size
                if request.near_addr is None
                else abs(allocation_addr - request.near_addr)
            )
            if best is None or metric < best.metric:
                best = _MappedCandidate(
                    block=block,
                    address=allocation_addr,
                    metric=metric,
                )
        return best

    def _first_valid_address(
        self,
        first: int,
        last: int,
        request: AllocationRequest,
    ) -> int | None:
        reference_addr = first if request.near_addr is None else request.near_addr
        for _, candidate_addr in self._iter_candidates_by_distance(
            first,
            last,
            reference_addr,
            request.align,
            request.align,
        ):
            if request.near_addr is not None:
                distance = abs(candidate_addr - request.near_addr)
                if request.max_dist is not None and distance > request.max_dist:
                    break
            validator = request.address_validator
            if validator is None or validator(candidate_addr):
                return candidate_addr
        return None

    def _claim_mapped_range(
        self,
        free_block: MappedBlock,
        allocation_addr: int,
        size: int,
    ) -> MappedBlock:
        offset = allocation_addr - free_block.mem_addr
        remaining = free_block.size - size - offset
        original_file_addr = free_block.file_addr
        original_mem_addr = free_block.mem_addr
        original_flag = free_block.flag
        original_load_mem_addr = free_block.load_mem_addr
        allocated = MappedBlock(
            file_addr=original_file_addr + offset,
            addr=allocation_addr,
            size=size,
            is_free=False,
            flag=original_flag,
            load_mem_addr=original_load_mem_addr + offset,
        )

        if remaining == 0:
            self.blocks[MappedBlock].remove(free_block)
        else:
            free_block.file_addr = original_file_addr + size + offset
            free_block.mem_addr = original_mem_addr + size + offset
            free_block.load_mem_addr = original_load_mem_addr + size + offset
            free_block.size = remaining
        if offset > 0:
            self.add_block(
                MappedBlock(
                    file_addr=original_file_addr,
                    addr=original_mem_addr,
                    size=offset,
                    is_free=True,
                    flag=original_flag,
                    load_mem_addr=original_load_mem_addr,
                )
            )
        self.add_block(allocated)
        return allocated

    @staticmethod
    def _iter_candidates_by_distance(
        first: int,
        last: int,
        near_addr: int,
        step: int,
        align: int,
    ) -> Iterator[tuple[int, int]]:
        candidate_count = (last - first) // step + 1

        def addresses(index: int) -> tuple[int, int]:
            candidate = first + index * step
            allocation_addr = candidate + (align - candidate % align) % align
            return candidate, allocation_addr

        # Find the first candidate at or above near_addr.
        low, high = 0, candidate_count
        while low < high:
            middle = (low + high) // 2
            if addresses(middle)[1] < near_addr:
                low = middle + 1
            else:
                high = middle

        left, right = low - 1, low
        # Merge candidates on both sides in distance order.
        while left >= 0 and right < candidate_count:
            left_addresses = addresses(left)
            right_addresses = addresses(right)
            if abs(left_addresses[1] - near_addr) <= abs(right_addresses[1] - near_addr):
                yield left_addresses
                left -= 1
            else:
                yield right_addresses
                right += 1
        while left >= 0:
            yield addresses(left)
            left -= 1
        while right < candidate_count:
            yield addresses(right)
            right += 1

    def _reserve_in_memory_gap(
        self, request: AllocationRequest, page_align: int
    ) -> tuple[int, int, int] | None:
        # Append at file-end, then choose the closest memory address with the
        # same p_align residue. This avoids alignment padding in the file.
        file_block = next(
            (block for block in self.blocks[FileBlock] if block.size == -1),
            None,
        )
        if file_block is None:
            return None
        file_addr = max(getattr(self.image, "file_size", file_block.addr), file_block.addr)
        residue = file_addr % page_align
        minimum_memory_address = getattr(
            self.image,
            "minimum_memory_address_for_new_segment",
            lambda _: None,
        )(file_addr)

        best, best_metric = None, None
        for mb in self.blocks[MemoryBlock]:
            if mb.size == -1 or mb.size < request.size:
                continue
            lower_bound = max(
                mb.addr,
                minimum_memory_address if minimum_memory_address is not None else mb.addr,
            )
            first = lower_bound + (residue - lower_bound) % page_align
            last_limit = mb.addr + mb.size - request.size
            last = last_limit - (last_limit - residue) % page_align
            if first > last:
                continue

            reference_addr = first if request.near_addr is None else request.near_addr
            # candidate is the segment start; allocation_addr includes alignment.
            for candidate, allocation_addr in self._iter_candidates_by_distance(
                first,
                last,
                reference_addr,
                page_align,
                request.align,
            ):
                required_size = allocation_addr - candidate + request.size
                if candidate + required_size > mb.addr + mb.size:
                    continue
                metric = mb.size
                if request.near_addr is not None:
                    distance = abs(allocation_addr - request.near_addr)
                    if request.max_dist is not None and distance > request.max_dist:
                        break
                    metric = distance
                validator = request.address_validator
                if validator is not None and not validator(allocation_addr):
                    continue
                if best_metric is None or metric < best_metric:
                    best, best_metric = (mb, candidate, required_size), metric
                break
        if best is None:
            return None

        mb, mem_addr, required_size = best
        available = (mb.addr + mb.size) - mem_addr
        block_size = min(available, max(self.CHUNK, required_size))
        prefix_size = mem_addr - mb.addr
        suffix_addr = mem_addr + block_size
        suffix_size = (mb.addr + mb.size) - suffix_addr
        if prefix_size > 0:
            mb.size = prefix_size
        else:
            self.blocks[MemoryBlock].remove(mb)
        if suffix_size > 0:
            self.blocks[MemoryBlock].append(MemoryBlock(addr=suffix_addr, size=suffix_size))
            self.blocks[MemoryBlock].sort()

        file_block.addr = max(file_block.addr, file_addr + block_size)
        return (file_addr, mem_addr, block_size)

    def _prospective_open_end_size(
        self,
        mem_addr: int,
        request: AllocationRequest,
        max_block_size: int | None = None,
    ) -> int | None:
        first = mem_addr + (request.align - mem_addr % request.align) % request.align
        reference_addr = first if request.near_addr is None else request.near_addr
        last_feasible = None
        if max_block_size is not None:
            last_limit = mem_addr + max_block_size - request.size
            last_feasible = last_limit - last_limit % request.align
            if first > last_feasible:
                return None

        # Finite distance limits define the complete search range. Otherwise,
        # bound arbitrary validator calls around the closest feasible address.
        search_center = reference_addr
        if last_feasible is not None and request.max_dist is None:
            search_center = min(max(search_center, first), last_feasible)
        if request.near_addr is not None and request.max_dist is not None:
            search_lower = request.near_addr - request.max_dist
            search_upper = request.near_addr + request.max_dist
        else:
            search_lower = search_center - self.CHUNK
            search_upper = max(first, search_center) + self.CHUNK
        search_start = max(first, search_lower)
        search_start += (request.align - search_start % request.align) % request.align
        search_end = max(first, search_upper)
        search_end -= search_end % request.align
        if last_feasible is not None:
            search_end = min(search_end, last_feasible)
        if search_start > search_end:
            if request.near_addr is not None and request.max_dist is not None:
                return None
            upper_candidate = search_start
            search_start = max(first, search_end)
            search_end = upper_candidate

        search_ranges = [(search_start, search_end)]
        if request.max_dist is None and search_start > first:
            fallback_end = first + self.CHUNK
            fallback_end -= fallback_end % request.align
            if last_feasible is not None:
                fallback_end = min(fallback_end, last_feasible)
            search_ranges.append((first, fallback_end))

        for range_start, range_end in search_ranges:
            for _, allocation_addr in self._iter_candidates_by_distance(
                range_start,
                range_end,
                reference_addr,
                request.align,
                request.align,
            ):
                if request.near_addr is not None:
                    distance = abs(allocation_addr - request.near_addr)
                    if request.max_dist is not None and distance > request.max_dist:
                        break
                validator = request.address_validator
                if validator is not None and not validator(allocation_addr):
                    continue
                required_size = allocation_addr - mem_addr + request.size
                if max_block_size is not None and required_size > max_block_size:
                    continue
                block_size = max(
                    self.extender.mapped_block_granularity,
                    required_size,
                )
                if max_block_size is not None:
                    block_size = min(block_size, max_block_size)
                return block_size
        return None

    def _extend_at_open_end(
        self,
        request: AllocationRequest,
        page_align: int,
    ) -> bool:
        # TODO: reuse finite FileBlock entries (inter-segment file slop).
        file_block = next(
            (block for block in self.blocks[FileBlock] if block.size == -1),
            None,
        )
        memory_block = next(
            (block for block in self.blocks[MemoryBlock] if block.size == -1),
            None,
        )
        if file_block is None or memory_block is None:
            return False

        file_addr = file_block.addr
        mem_addr = memory_block.addr + (file_addr - memory_block.addr) % page_align
        block_size = self._prospective_open_end_size(
            mem_addr,
            request,
        )
        if block_size is None:
            return False

        file_block.addr += block_size
        memory_block.addr = mem_addr + block_size
        self._add_new_mapped_block(
            MappedBlock(
                file_addr=file_addr,
                addr=mem_addr,
                size=block_size,
                flag=request.flag,
            )
        )
        return True

    def allocate(
        self,
        size: int,
        *,
        flag: MemoryFlag = MemoryFlag.RWX,
        align: int = 1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> MappedBlock:
        # near_addr: prefer blocks close to this address.
        # max_dist: reject existing free blocks farther than this; falls
        # through to carving a new LOAD segment in a closer MemoryBlock.
        logger.debug(
            f"allocate size={hex(size)} flag={flag!r} align={hex(align)}"
            + (f" near={hex(near_addr)}" if near_addr is not None else "")
            + (f" max_dist={hex(max_dist)}" if max_dist is not None else "")
        )
        request = AllocationRequest(
            size=size,
            flag=flag,
            align=align,
            near_addr=near_addr,
            max_dist=max_dist,
            address_validator=address_validator,
        )
        created_new_block = False
        while True:
            block = self._allocate_from_mapped_blocks(request)
            if block:
                return block
            if created_new_block:
                raise RuntimeError("New mapped block cannot satisfy allocation")
            if not self.extender.extend(self, request):
                raise MemoryError("Insufficient memory")
            created_new_block = True

    def free(self, block: Block) -> None:
        block.is_free = True
        blocks = self.blocks[type(block)]
        blocks.sort()
        self.coalesce(blocks)

    @staticmethod
    def coalesce(blocks: list[BlockT]) -> None:
        index = 0
        while index + 1 < len(blocks):
            if blocks[index].coalesce(blocks[index + 1]):
                del blocks[index + 1]
            else:
                index += 1

    def _discard_free_mapped_range(self, start: int, end: int) -> None:
        remaining_blocks = []
        for block in self.blocks[MappedBlock]:
            block_end = block.mem_addr + block.size
            if not block.is_free or block_end <= start or block.mem_addr >= end:
                remaining_blocks.append(block)
                continue
            if block.mem_addr < start:
                remaining_blocks.append(
                    MappedBlock(
                        file_addr=block.file_addr,
                        addr=block.mem_addr,
                        size=start - block.mem_addr,
                        is_free=True,
                        flag=block.flag,
                        load_mem_addr=block.load_mem_addr,
                    )
                )
            if block_end > end:
                offset = end - block.mem_addr
                remaining_blocks.append(
                    MappedBlock(
                        file_addr=block.file_addr + offset,
                        addr=end,
                        size=block_end - end,
                        is_free=True,
                        flag=block.flag,
                        load_mem_addr=block.load_mem_addr + offset,
                    )
                )
        remaining_blocks.sort()
        self.blocks[MappedBlock] = remaining_blocks
        self.coalesce(remaining_blocks)

    def finalize(self) -> None:
        allocated_blocks = [block for block in self.blocks[MappedBlock] if not block.is_free]
        retained_blocks: list[MappedBlock] = []
        for block in self.new_mapped_blocks:
            block_end = block.mem_addr + block.size
            used_end = max(
                (
                    min(mapped.mem_addr + mapped.size, block_end)
                    for mapped in allocated_blocks
                    if mapped.mem_addr < block_end
                    and mapped.mem_addr + mapped.size > block.mem_addr
                ),
                default=block.mem_addr,
            )
            if used_end < block_end:
                self._discard_free_mapped_range(used_end, block_end)
            if used_end > block.mem_addr:
                block.size = used_end - block.mem_addr
                retained_blocks.append(block)

        self.new_mapped_blocks = retained_blocks
        for block in self.new_mapped_blocks:
            self.image.file_size = max(self.image.file_size, block.file_addr + block.size)
        logger.debug(f"finalized blocks:\n{pformat(list(self.blocks.values()))}")
        logger.debug(f"new mapped blocks:\n{pformat(self.new_mapped_blocks)}")
