import sys
from contextlib import AbstractContextManager
from typing import Annotated, Any

from pydantic import Field

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.allocation_manager import AllocationManager
from patcherex2.components.binary_analyzer.angr import AngrAnalyzer
from patcherex2.components.image import ImageBackend
from patcherex2.components.image.raw import RawImageBackend
from patcherex2.components.placement_strategies import (
    RawBareMetalAllocationExtender,
    RawExplicitPlacement,
)
from patcherex2.models import FrozenPatcherexModel
from patcherex2.targets.arm_bare import ARM_BARE_RUNTIME
from patcherex2.targets.profiles import ARM_BARE
from patcherex2.targets.target import ComponentFactory, ImageProfile, TargetDefinition


class ArmRawImageBackend(RawImageBackend):
    """Linear raw image with an explicit load base and extension fill value."""

    def __init__(
        self,
        binary_path: str,
        *,
        image_base: int,
        fill_byte: int = 0xFF,
    ) -> None:
        if not isinstance(image_base, int) or image_base < 0:
            raise ValueError("image_base must be a non-negative integer")
        if not isinstance(fill_byte, int) or not 0 <= fill_byte <= 0xFF:
            raise ValueError("fill_byte must be between 0x00 and 0xff")
        self.image_base = image_base
        self.fill_byte = fill_byte
        super().__init__(binary_path)

    @override
    def save_binary(self, filename: str | None = None) -> None:
        if filename is None:
            filename = f"{self.binary_path}.patched"
        content = bytearray(self._original)
        if len(content) < self.file_size:
            content.extend(bytes([self.fill_byte]) * (self.file_size - len(content)))
        for update in self.file_updates:
            start = update["offset"]
            content[start : start + len(update["content"])] = update["content"]
        with open(filename, "wb") as file_handle:
            file_handle.write(content)


class ArmRawImageConfig(FrozenPatcherexModel):
    """File mapping and extension policy for an ARM raw image."""

    image_base: Annotated[int, Field(ge=0)]
    fill_byte: Annotated[int, Field(ge=0, le=0xFF)] = 0xFF

    def build(self, binary_path: str) -> ArmRawImageBackend:
        """Build an image using this validated mapping and fill policy."""
        return ArmRawImageBackend(binary_path, image_base=self.image_base, fill_byte=self.fill_byte)


def _raw_allocator(binary_analyzer: Any, image: Any) -> AllocationManager:
    return AllocationManager(
        binary_analyzer=binary_analyzer,
        image=image,
        extender=RawBareMetalAllocationExtender(),
    )


def _raw_backend(binary_path: str) -> ArmRawImageBackend:
    raise ValueError("Raw ARM images require an image override: ArmRawImageConfig(...).build")


def _raw_analyzer(binary_path: str, image: ImageBackend) -> AbstractContextManager[AngrAnalyzer]:
    if not isinstance(image, ArmRawImageBackend):
        raise TypeError("Raw ARM analyzer requires ArmRawImageBackend")
    return AngrAnalyzer.load_binary(
        binary_path,
        angr_kwargs={
            "main_opts": {
                "backend": "blob",
                "arch": "ARMEL",
                "base_addr": image.image_base,
                "entry_point": image.image_base,
            },
            "auto_load_libs": False,
        },
        angr_cfg_kwargs={"normalize": True, "data_references": True},
    )


def _raw_placement() -> RawExplicitPlacement:
    raise ValueError("Raw ARM images require a RawExplicitPlacement override")


ARM_RAW_IMAGE = ImageProfile(
    name="arm-raw",
    backend=ComponentFactory(
        role="image backend",
        default="raw",
        choices={"raw": _raw_backend},
    ),
    allocator=ComponentFactory(
        role="allocation manager",
        default="explicit",
        choices={"explicit": _raw_allocator},
    ),
    placement=ComponentFactory(
        role="placement strategy",
        default="explicit",
        choices={"explicit": _raw_placement},
    ),
)

ARM_RAW_BARE = TargetDefinition(
    name="arm-raw-bare",
    architecture=ARM_BARE,
    image=ARM_RAW_IMAGE,
    analyzer=ComponentFactory(
        role="binary analyzer",
        default="angr",
        choices={"angr": _raw_analyzer},
    ),
    runtime=ARM_BARE_RUNTIME,
)
