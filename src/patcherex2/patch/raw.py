"""Contains patches that modify the binary at the byte level."""

from __future__ import annotations

import sys
from enum import Enum
from typing import TYPE_CHECKING, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.patch import Patch

if TYPE_CHECKING:
    from patcherex2.session import PatchSession


@final
class AddressType(Enum):
    """Address interpretation used by a raw byte patch."""

    MEMORY = "memory"
    FILE = "file"


class ModifyRawBytesPatch(Patch):
    """Overwrite bytes using an explicit address interpretation."""

    def __init__(
        self,
        addr: int,
        new_bytes: bytes,
        *,
        addr_type: AddressType = AddressType.MEMORY,
    ) -> None:
        """Initialize a raw byte modification.

        Args:
            addr: Starting memory address or file offset.
            new_bytes: Replacement bytes.
            addr_type: How to interpret ``addr``.
        """
        self.addr: int = addr
        self.new_bytes: bytes = new_bytes
        self.addr_type: AddressType = addr_type

    @final
    @override
    def apply(self, p: PatchSession) -> None:
        """Apply the byte modification to a patch session."""
        match self.addr_type:
            case AddressType.FILE:
                p.image.update_binary_content(self.addr, self.new_bytes)
            case AddressType.MEMORY:
                p.image.update_binary_content(
                    p.binary_analyzer.mem_addr_to_file_offset(self.addr), self.new_bytes
                )
            case other:
                raise NotImplementedError(f"Unimplemented address type {other}")
