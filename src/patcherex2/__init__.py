# ruff: noqa
from importlib import metadata

from patcherex2.patch.data import InsertDataPatch, ModifyDataPatch, RemoveDataPatch
from patcherex2.patch.function import (
    InsertFunctionPatch,
    ModifyFunctionPatch,
)
from patcherex2.patch.instruction import (
    InsertInstructionPatch,
    InstructionPatchLanguage,
    ModifyInstructionPatch,
    RemoveInstructionPatch,
)
from patcherex2.patch.raw import AddressType, ModifyRawBytesPatch
from patcherex2.session import PatchSession
from patcherex2.targets import (
    ArmBareMetalRuntimeConfig,
    ArmRawImageConfig,
    BareMetalAddressSpace,
    ComponentOverrides,
    ComponentSelections,
    TargetConfig,
)

__version__: str = metadata.version("patcherex2")

__all__: list[str] = [
    "AddressType",
    "ArmBareMetalRuntimeConfig",
    "ArmRawImageConfig",
    "BareMetalAddressSpace",
    "ComponentOverrides",
    "ComponentSelections",
    "InsertDataPatch",
    "InsertFunctionPatch",
    "InsertInstructionPatch",
    "InstructionPatchLanguage",
    "ModifyDataPatch",
    "ModifyFunctionPatch",
    "ModifyInstructionPatch",
    "ModifyRawBytesPatch",
    "PatchSession",
    "RemoveDataPatch",
    "RemoveInstructionPatch",
    "TargetConfig",
]
