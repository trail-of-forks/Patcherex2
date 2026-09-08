from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from patcherex2.components.allocation_manager import (
        AllocationManager,
    )
    from patcherex2.components.binary_analyzer import BinaryAnalyzer

logger = logging.getLogger(__name__)


class FileUpdate(TypedDict):
    """A staged replacement at a file offset."""

    offset: int
    content: bytes


class ImageBackend(ABC):
    """Abstract interface for reading, modifying, and emitting an image."""

    def __init__(self, binary_path: str, *, file_size: int) -> None:
        if not isinstance(file_size, int) or file_size < 0:
            raise ValueError("file_size must be non-negative")
        self.binary_path = binary_path
        self.file_size = file_size
        self.file_updates: list[FileUpdate] = []

    @property
    @abstractmethod
    def is_position_independent(self) -> bool:
        """Whether addresses in the image may change at load time."""

    def _record_file_update(self, offset: int, new_content: bytes) -> None:
        if offset < 0:
            raise ValueError(f"Cannot update a negative file offset: {offset}")
        new_content = bytes(new_content)
        if not new_content:
            return

        new_end = offset + len(new_content)
        retained_updates: list[FileUpdate] = []
        overlapping_updates: list[FileUpdate] = []
        for update in self.file_updates:
            old_start = update["offset"]
            old_content = update["content"]
            old_end = old_start + len(old_content)
            if offset >= old_end or old_start >= new_end:
                retained_updates.append(update)
                continue

            overlap_start = max(offset, old_start)
            overlap_end = min(new_end, old_end)
            new_slice = new_content[overlap_start - offset : overlap_end - offset]
            old_slice = old_content[overlap_start - old_start : overlap_end - old_start]
            if new_slice != old_slice:
                raise ValueError(
                    f"Cannot update file interval [{hex(offset)}, {hex(new_end)}) "
                    f"because it conflicts with a previous update interval "
                    f"[{hex(old_start)}, {hex(old_end)})"
                )
            overlapping_updates.append(update)

        if overlapping_updates:
            update = self._merge_file_updates(offset, new_content, overlapping_updates)
        else:
            update = FileUpdate(offset=offset, content=new_content)

        retained_updates.append(update)
        retained_updates.sort(key=lambda item: item["offset"])
        self.file_updates = retained_updates
        self.file_size = max(self.file_size, new_end)

    @staticmethod
    def _merge_file_updates(
        offset: int,
        new_content: bytes,
        overlapping_updates: list[FileUpdate],
    ) -> FileUpdate:
        new_end = offset + len(new_content)
        merged_start = min([offset] + [update["offset"] for update in overlapping_updates])
        merged_end = max(
            [new_end]
            + [update["offset"] + len(update["content"]) for update in overlapping_updates]
        )
        merged_content = bytearray(merged_end - merged_start)
        for update in overlapping_updates:
            start = update["offset"] - merged_start
            end = start + len(update["content"])
            merged_content[start:end] = update["content"]
        start = offset - merged_start
        merged_content[start : start + len(new_content)] = new_content
        return {"offset": merged_start, "content": bytes(merged_content)}

    def _read_size(self, offset: int, size: int) -> int:
        if offset < 0:
            raise ValueError(f"Cannot read a negative file offset: {offset}")
        if size < 0:
            raise ValueError(f"Cannot read a negative size: {size}")
        return min(size, max(0, self.file_size - offset))

    def _overlay_file_updates(self, offset: int, original_content: bytes) -> bytes:
        content = bytearray(original_content)
        read_end = offset + len(content)
        for update in self.file_updates:
            update_start = update["offset"]
            update_end = update_start + len(update["content"])
            overlap_start = max(offset, update_start)
            overlap_end = min(read_end, update_end)
            if overlap_start >= overlap_end:
                continue
            content[overlap_start - offset : overlap_end - offset] = update["content"][
                overlap_start - update_start : overlap_end - update_start
            ]
        return bytes(content)

    @abstractmethod
    def finalize(
        self,
        allocation_manager: AllocationManager,
        binary_analyzer: BinaryAnalyzer,
    ) -> None:
        """Finalize image metadata after all patches have been applied."""

    def initialize_allocation_manager(
        self,
        allocation_manager: AllocationManager,
    ) -> None:
        """Populate format-derived allocation state, if the format provides it."""
        del allocation_manager

    @abstractmethod
    def save_binary(self, filename: str | None = None) -> None:
        """Write the finalized image to disk."""

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        """Stage bytes for replacement at a file-relative offset."""
        logger.debug(
            "Updating offset %s with content (%d bytes) %s",
            hex(offset),
            len(new_content),
            new_content.hex(),
        )
        self._record_file_update(offset, new_content)

    @abstractmethod
    def get_binary_content(self, offset: int, size: int) -> bytes:
        """Read image bytes with staged updates overlaid."""

    def append_to_binary_content(self, new_content: bytes) -> None:
        """Append bytes to the file-backed image."""
        self.update_binary_content(self.file_size, new_content)

    @abstractmethod
    def page_alignment(self) -> int:
        """Return the alignment required for newly mapped image data."""

    def minimum_memory_address_for_new_segment(self, file_offset: int) -> int | None:
        return None
