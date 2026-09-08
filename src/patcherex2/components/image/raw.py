from __future__ import annotations

import sys

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.image import ImageBackend


class RawImageBackend(ImageBackend):
    """Backend for an unstructured byte-for-byte image."""

    def __init__(self, binary_path: str) -> None:
        with open(binary_path, "rb") as f:
            self._original = f.read()
        super().__init__(binary_path, file_size=len(self._original))

    @property
    @override
    def is_position_independent(self) -> bool:
        return False

    @override
    def finalize(self, allocation_manager, binary_analyzer) -> None:
        """Raw images have no metadata to finalize."""

    @override
    def save_binary(self, filename: str | None = None) -> None:
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            f.write(self._original)
            for update in self.file_updates:
                f.seek(update["offset"])
                f.write(update["content"])

    @override
    def get_binary_content(self, offset: int, size: int) -> bytes:
        read_size = self._read_size(offset, size)
        original_content = self._original[offset : offset + read_size].ljust(read_size, b"\x00")
        return self._overlay_file_updates(offset, original_content)

    @override
    def page_alignment(self) -> int:
        return 0x1000
