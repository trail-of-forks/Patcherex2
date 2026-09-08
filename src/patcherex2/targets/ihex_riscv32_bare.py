import logging
from contextlib import AbstractContextManager

from patcherex2.components.binary_analyzer.angr import AngrAnalyzer
from patcherex2.components.binary_analyzer.ida import IDAAnalyzer
from patcherex2.components.image import ImageBackend
from patcherex2.targets.profiles import IHEX_IMAGE, RISCV32_BARE
from patcherex2.targets.target import ComponentFactory, TargetDefinition

logger = logging.getLogger(__name__)


def _angr_analyzer(binary_path: str, _image: ImageBackend) -> AbstractContextManager[AngrAnalyzer]:
    return AngrAnalyzer.load_binary(
        binary_path,
        angr_kwargs={"arch": "riscv32", "auto_load_libs": False},
        angr_cfg_kwargs={"normalize": True, "data_references": True},
    )


def _ida_analyzer(binary_path: str, _image: ImageBackend) -> AbstractContextManager[IDAAnalyzer]:
    return IDAAnalyzer.load_binary(binary_path, processor="riscv")


RISCV32_IHEX_BARE = TargetDefinition(
    name="riscv32-ihex-bare",
    architecture=RISCV32_BARE,
    image=IHEX_IMAGE,
    analyzer=ComponentFactory(
        role="binary analyzer",
        default="ida",
        choices={"angr": _angr_analyzer, "ida": _ida_analyzer},
    ),
)
