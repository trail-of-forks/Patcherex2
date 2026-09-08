from typing import Any

from patcherex2.components.allocation_manager import AllocationManager
from patcherex2.components.image.bare_elf import BareMetalElfImageBackend
from patcherex2.components.placement_strategies import (
    ElfBareMetalAllocationExtender,
    ElfExplicitPlacement,
)
from patcherex2.targets.arm_bare import ARM_BARE_RUNTIME
from patcherex2.targets.profiles import ARM_BARE, standard_analyzer_factory
from patcherex2.targets.target import ComponentFactory, ImageProfile, TargetDefinition


def _elf_bare_allocator(binary_analyzer: Any, image: Any) -> AllocationManager:
    return AllocationManager(
        binary_analyzer=binary_analyzer,
        image=image,
        extender=ElfBareMetalAllocationExtender(),
    )


def _elf_bare_backend(binary_path: str) -> BareMetalElfImageBackend:
    return BareMetalElfImageBackend(binary_path)


def _elf_bare_placement() -> ElfExplicitPlacement:
    raise ValueError("Bare-metal ELF images require an ElfExplicitPlacement override")


ARM_BARE_ELF_IMAGE = ImageProfile(
    name="arm-bare-elf",
    backend=ComponentFactory(
        role="image backend",
        default="elf",
        choices={"elf": _elf_bare_backend},
    ),
    allocator=ComponentFactory(
        role="allocation manager",
        default="explicit",
        choices={"explicit": _elf_bare_allocator},
    ),
    placement=ComponentFactory(
        role="placement strategy",
        default="explicit",
        choices={"explicit": _elf_bare_placement},
    ),
)

ARM_ELF_BARE = TargetDefinition(
    name="arm-elf-bare",
    architecture=ARM_BARE,
    image=ARM_BARE_ELF_IMAGE,
    analyzer=standard_analyzer_factory(),
    runtime=ARM_BARE_RUNTIME,
)
