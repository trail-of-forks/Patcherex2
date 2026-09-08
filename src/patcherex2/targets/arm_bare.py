from typing import Annotated

from pydantic import BeforeValidator, Field

from patcherex2.components.load_models import ArmBareMetalLoadModel
from patcherex2.models import FrozenPatcherexModel
from patcherex2.targets.target import ComponentFactory, RuntimeProfile

NonNegativeAddress = Annotated[int, Field(ge=0)]
InsertPoints = Annotated[tuple[NonNegativeAddress, ...], BeforeValidator(tuple)]


class ArmBareMetalRuntimeConfig(FrozenPatcherexModel):
    """Runtime initialization points for an ARM bare-metal image."""

    insert_points: InsertPoints = ()

    def build(self) -> ArmBareMetalLoadModel:
        """Construct the runtime policy from validated initialization points."""
        return ArmBareMetalLoadModel(self.insert_points)


def _arm_bare_load_model() -> ArmBareMetalLoadModel:
    return ArmBareMetalLoadModel(())


ARM_BARE_RUNTIME = RuntimeProfile(
    name="arm-bare",
    load_model=ComponentFactory(
        role="load model",
        default="bare_metal",
        choices={"bare_metal": _arm_bare_load_model},
    ),
)
