from __future__ import annotations

from typing import final

from patcherex2.patch.raw import AddressType, ModifyRawBytesPatch


@final
class RemoveDataPatch(ModifyRawBytesPatch):
    """Replace a runtime memory range with zero bytes."""

    def __init__(self, addr: int, size: int) -> None:
        """Initialize a data removal.

        Args:
            addr: Runtime memory address at which to begin writing zeroes.
            size: Number of bytes to replace.
        """
        super().__init__(addr, b"\x00" * size, addr_type=AddressType.MEMORY)
