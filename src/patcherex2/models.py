from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class PatcherexModel(BaseModel):
    """Strict validated model shared by Patcherex2 domain records."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        strict=True,
    )


class FrozenPatcherexModel(PatcherexModel):
    """Immutable validated model for declarations and discovered facts."""

    model_config = ConfigDict(frozen=True)
