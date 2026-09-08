from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from os import PathLike
from pathlib import Path
from typing import ClassVar, final

from typing_extensions import Self

from patcherex2.components.allocation_manager import AllocationManager
from patcherex2.components.arch import ArchitectureInfo
from patcherex2.components.assembler import Assembler, AssemblyBackend
from patcherex2.components.binary_analyzer import BinaryAnalyzer
from patcherex2.components.compilers import Compiler
from patcherex2.components.disassemblers.disassembler import Disassembler
from patcherex2.components.image import ImageBackend
from patcherex2.components.load_models import LoadModel
from patcherex2.components.placement_strategies import PlacementStrategy
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.components.utils.utils import Utils
from patcherex2.patch import Patch
from patcherex2.targets.builder import BuiltComponents, ComponentBuilder
from patcherex2.targets.target import TargetConfig, TargetDefinition

logging.Logger.manager.loggerDict["patcherex"] = logging.Logger.manager.loggerDict["patcherex2"]
logger = logging.getLogger(__name__)


@final
class PatchSession:
    """A binary-patching unit assembled from injected components.

    Use :meth:`load_binary` when components must be constructed. Directly
    instantiated sessions are pure consumers and own none of their dependencies.
    """

    COMPONENT_BUILDER: ClassVar[ComponentBuilder] = ComponentBuilder()

    def __init__(
        self,
        *,
        binary_path: Path,
        target: TargetDefinition,
        archinfo: ArchitectureInfo,
        binary_analyzer: BinaryAnalyzer,
        image: ImageBackend,
        allocation_manager: AllocationManager,
        symbol_resolver: SymbolResolver,
        assembler: Assembler,
        disassembler: Disassembler,
        compiler: Compiler,
        utils: Utils,
        placement_strategy: PlacementStrategy | None,
        load_model: LoadModel | None,
    ) -> None:
        """Initialize a session from an already-constructed component graph.

        Args:
            binary_path: Path of the binary to patch.
            target: Target declaration governing the component graph.
            archinfo: Static architecture information.
            binary_analyzer: Binary analysis implementation.
            image: Image reading and rewriting implementation.
            allocation_manager: Patch storage allocator.
            symbol_resolver: Existing and patch-added symbol resolver.
            assembler: Symbol-resolving assembler.
            disassembler: Machine-code disassembler.
            compiler: Source compiler.
            utils: Architecture-aware patching operations.
            placement_strategy: Optional image placement policy.
            load_model: Optional runtime materialization policy.
        """
        self.binary_path: Path = binary_path
        self.target: TargetDefinition = target
        self.patches: list[Patch] = []
        self.archinfo: ArchitectureInfo = archinfo
        self.binary_analyzer: BinaryAnalyzer = binary_analyzer
        self.image: ImageBackend = image
        self.allocation_manager: AllocationManager = allocation_manager
        self.symbol_resolver: SymbolResolver = symbol_resolver
        self.assembler: Assembler = assembler
        self.disassembler: Disassembler = disassembler
        self.compiler: Compiler = compiler
        self.utils: Utils = utils
        self.placement_strategy: PlacementStrategy | None = placement_strategy
        self.load_model: LoadModel | None = load_model

    @property
    def added_functions(self) -> list[str]:
        """Addresses of functions added during this session."""
        return self.utils.added_functions

    @property
    def symbols(self) -> dict[str, int]:
        """Symbols registered by patches in this session."""
        return self.symbol_resolver.patch_symbols

    @classmethod
    @contextmanager
    def load_binary(
        cls,
        binary_path: str | PathLike[str],
        target: TargetDefinition,
        config: TargetConfig | None = None,
        *,
        binary_analyzer: BinaryAnalyzer | None = None,
        assembly_backend: AssemblyBackend | None = None,
        compiler: Compiler | None = None,
    ) -> Generator[Self]:
        """Yield a session and close all session-owned resources afterward.

        Injected implementations are borrowed. In particular, this supports an
        analyzer backed by an application the caller already has open without
        transferring ownership of that application's lifetime to Patcherex2.
        """
        binary_path = Path(binary_path)
        with ExitStack() as resource_stack:
            yield cls.from_build_components(
                binary_path,
                target,
                cls.COMPONENT_BUILDER.build(
                    binary_path,
                    target,
                    config or TargetConfig(),
                    resource_stack=resource_stack,
                    binary_analyzer=binary_analyzer,
                    assembly_backend=assembly_backend,
                    compiler=compiler,
                ),
            )

    @classmethod
    def from_build_components(
        cls, binary_path: Path, target: TargetDefinition, components: BuiltComponents
    ) -> Self:
        return cls(
            binary_path=binary_path,
            target=target,
            archinfo=components.archinfo,
            binary_analyzer=components.binary_analyzer,
            image=components.image,
            allocation_manager=components.allocation_manager,
            symbol_resolver=components.symbol_resolver,
            assembler=components.assembler,
            disassembler=components.disassembler,
            compiler=components.compiler,
            utils=components.utils,
            placement_strategy=components.placement_strategy,
            load_model=components.load_model,
        )

    def apply_patches(self) -> None:
        """Apply all queued patches and finalize the output image."""
        logger.debug("Applying patches: %s", self.patches)
        for patch in self.patches:
            patch.apply(self)
        if self.load_model is not None:
            self.load_model.prepare(self)
        self.image.finalize(
            self.allocation_manager,
            self.binary_analyzer,
        )

    def save_binary(self, filename: str | None = None) -> None:
        """Save the patched binary, by default to ``<filename>.patched``."""
        self.image.save_binary(filename)
