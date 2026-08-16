from __future__ import annotations

import logging

from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


class Binary(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        with open(binary_path, "rb") as f:
            self._original = f.read()
        self.file_size = len(self._original)
        self.file_updates = []

    def _init_memory_analysis(self) -> None:
        pass

    def finalize(self) -> None:
        pass

    def save_binary(self, filename: str | None = None) -> None:
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            f.write(self._original)
            for update in self.file_updates:
                f.seek(update["offset"])
                f.write(update["content"])

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        logger.debug(
            f"Updating offset {hex(offset)} with content ({len(new_content)} bytes) {new_content.hex()}"
        )
        self._record_file_update(offset, new_content)

    def get_binary_content(self, offset: int, size: int) -> bytes:
        read_size = self._read_size(offset, size)
        original_content = self._original[offset : offset + read_size].ljust(
            read_size, b"\x00"
        )
        return self._overlay_file_updates(offset, original_content)

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.update_binary_content(self.file_size, new_content)
