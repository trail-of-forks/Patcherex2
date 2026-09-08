from __future__ import annotations

from typing import final

from patcherex2.patch.raw import AddressType, ModifyRawBytesPatch


@final
class ModifyDataPatch(ModifyRawBytesPatch):
    """Overwrite bytes at a runtime memory address."""

    def __init__(self, addr: int, new_bytes: bytes) -> None:
        """Initialize a memory-addressed data modification."""
        super().__init__(addr, new_bytes, addr_type=AddressType.MEMORY)
