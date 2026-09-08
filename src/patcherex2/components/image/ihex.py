from __future__ import annotations

import io
import sys
from typing import cast

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import intelhex

from patcherex2.components.image import ImageBackend


class IHexImageBackend(ImageBackend):
    """Backend for an Intel HEX image."""

    def __init__(self, binary_path: str) -> None:
        self._ihex = intelhex.IntelHex(binary_path)
        super().__init__(binary_path, file_size=cast(int, self._ihex.maxaddr()) + 1)

    @property
    @override
    def is_position_independent(self) -> bool:
        return False

    @override
    def finalize(self, allocation_manager, binary_analyzer) -> None:
        """Intel HEX updates require no separate metadata finalization."""

    @override
    def save_binary(self, filename: str | None = None) -> None:
        for update in self.file_updates:
            self._ihex.puts(update["offset"], update["content"])
        if filename is None:
            filename = f"{self.binary_path}.patched"
        sio = io.StringIO()
        self._ihex.write_hex_file(sio, byte_count=0x20)
        final_content = sio.getvalue()
        sio.close()
        entry_point = ""
        final = ""
        for line in final_content.splitlines():
            if line.startswith(":04000005"):
                entry_point = line
            elif line == ":00000001FF":
                final += entry_point + "\n"
                final += line + "\n"
            else:
                final += line + "\n"

        with open(filename, "w") as f:
            f.write(final)

    @override
    def get_binary_content(self, offset: int, size: int) -> bytes:
        read_size = self._read_size(offset, size)
        if read_size == 0:
            return b""
        original_content = bytes(self._ihex.tobinarray(start=offset, size=read_size))
        return self._overlay_file_updates(offset, original_content)

    @override
    def page_alignment(self) -> int:
        return 0x1000
