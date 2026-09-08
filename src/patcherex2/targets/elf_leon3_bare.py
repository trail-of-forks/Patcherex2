import logging
import sys
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.image import ImageBackend
from patcherex2.targets.profiles import ELF_IMAGE, SPARC_BARE
from patcherex2.targets.target import ComponentFactory, TargetDefinition

from ..components.allocation_manager import (
    MappedBlock,
    MemoryFlag,
)
from ..components.binary_analyzer.angr import AngrAnalyzer
from ..components.binary_analyzer.ghidra import GhidraAnalyzer
from ..components.image.elf import ElfImageBackend

logger = logging.getLogger(__name__)


class Leon3ElfImageBackend(ElfImageBackend):
    """ELF backend for the LEON3 bare-metal memory layout."""

    @override
    def _init_memory_analysis(self, allocation_manager) -> None:
        # remove all non-RWX segments
        self._segments = [s for s in self._segments if s["p_flags"] & 0b111 == 0b111]
        block = MappedBlock(
            file_addr=self._segments[0]["p_offset"],
            addr=self._segments[0]["p_vaddr"],
            size=self._segments[0]["p_memsz"],
            is_free=False,
            flag=MemoryFlag.RWX,
        )
        allocation_manager.add_block(block)


def _leon3_backend(binary_path: str) -> Leon3ElfImageBackend:
    return Leon3ElfImageBackend(binary_path)


def _angr_analyzer(
    binary_path: str,
    _image: ImageBackend,
    *,
    config: Mapping[str, Any] | None = None,
) -> AbstractContextManager[AngrAnalyzer]:
    return AngrAnalyzer.load_binary(binary_path, **dict(config or {}))


def _ghidra_analyzer(
    binary_path: str,
    _image: ImageBackend,
    *,
    config: Mapping[str, Any] | None = None,
) -> AbstractContextManager[GhidraAnalyzer]:
    return GhidraAnalyzer.load_binary(binary_path, **dict(config or {}))


LEON3_ELF_IMAGE = ELF_IMAGE.model_copy(
    update={
        "name": "leon3-elf",
        "backend": ComponentFactory(
            role="image backend",
            default="leon3",
            choices={"leon3": _leon3_backend},
        ),
    }
)

LEON3_ELF_BARE = TargetDefinition(
    name="leon3-elf-bare",
    architecture=SPARC_BARE,
    image=LEON3_ELF_IMAGE,
    analyzer=ComponentFactory(
        role="binary analyzer",
        default="angr",
        choices={"angr": _angr_analyzer, "ghidra": _ghidra_analyzer},
    ),
)
