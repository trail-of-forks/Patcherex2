from __future__ import annotations

import sys
from typing import TYPE_CHECKING, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.allocation_manager import MemoryFlag
from patcherex2.patch import Patch

if TYPE_CHECKING:
    from patcherex2.session import PatchSession


@final
class InsertDataPatch(Patch):
    """Insert data at a file offset or allocate it under a symbol name."""

    def __init__(self, addr_or_name: int | str, data: bytes) -> None:
        """Initialize a data insertion.

        Args:
            addr_or_name: Existing file offset, or a name for newly allocated data.
            data: Bytes to write.
        """
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.data = data

    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the data insertion to a patch session."""
        if self.addr is not None:
            p.image.update_binary_content(self.addr, self.data)
        elif self.name:
            block = p.allocation_manager.allocate(len(self.data), flag=MemoryFlag.RW)
            p.symbols[self.name] = block.mem_addr
            p.image.update_binary_content(block.file_addr, self.data)
