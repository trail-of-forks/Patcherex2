from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from patcherex2.session import PatchSession


class Patch(Protocol):
    """Operation that can modify a configured PatchSession instance."""

    def apply(self, p: PatchSession) -> None:
        """Apply this patch to ``p``."""
        ...
