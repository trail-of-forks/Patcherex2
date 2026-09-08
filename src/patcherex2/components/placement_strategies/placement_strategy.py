from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patcherex2.components.allocation_manager import (
        AllocationManager,
    )
    from patcherex2.components.image import ImageBackend


class PlacementStrategy(ABC):
    """Configures the source of new file, load, and runtime address ranges."""

    @abstractmethod
    def initialize(
        self,
        *,
        image: ImageBackend,
        allocation_manager: AllocationManager,
    ) -> None:
        """Register placement resources after all target components exist."""
