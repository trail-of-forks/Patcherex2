from __future__ import annotations

from contextlib import AbstractContextManager, ExitStack
from pathlib import Path
from typing import final

from patcherex2.components.allocation_manager import (
    AllocationManager,
)
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
from patcherex2.models import FrozenPatcherexModel
from patcherex2.targets.target import (
    TargetConfig,
    TargetDefinition,
)


@final
class BuiltComponents(FrozenPatcherexModel):
    """Live component graph produced from a target declaration."""

    archinfo: ArchitectureInfo
    binary_analyzer: BinaryAnalyzer
    image: ImageBackend
    allocation_manager: AllocationManager
    symbol_resolver: SymbolResolver
    assembler: Assembler
    disassembler: Disassembler
    compiler: Compiler
    utils: Utils
    placement_strategy: PlacementStrategy | None
    load_model: LoadModel | None


@final
class ComponentBuilder:
    """Materialize target declarations in dependency order."""

    def build(
        self,
        binary_path: Path,
        target: TargetDefinition,
        config: TargetConfig,
        *,
        resource_stack: ExitStack,
        binary_analyzer: BinaryAnalyzer | None = None,
        assembly_backend: AssemblyBackend | None = None,
        compiler: Compiler | None = None,
    ) -> BuiltComponents:
        selections = config.selections
        overrides = config.overrides
        architecture = target.architecture
        image_profile = target.image
        placement = self._build_placement(target, config)
        load_model = self._build_load_model(target, config)

        archinfo = architecture.info
        image_builder = overrides.image
        if image_builder is None:
            image_builder = image_profile.backend.select(selections.image)
        image = image_builder(str(binary_path))
        analyzer = self._build_analyzer(
            binary_path,
            target,
            config,
            image,
            resource_stack=resource_stack,
            binary_analyzer=binary_analyzer,
        )
        allocator_builder = overrides.allocation_manager
        if allocator_builder is None:
            allocator_builder = image_profile.allocator.select(selections.allocation_manager)
        allocation_manager = allocator_builder(analyzer, image)
        image.initialize_allocation_manager(allocation_manager)
        if placement is not None:
            placement.initialize(image=image, allocation_manager=allocation_manager)

        symbol_resolver = SymbolResolver(analyzer)
        assembler = self._build_assembler(
            target,
            config,
            symbol_resolver,
            assembly_backend=assembly_backend,
        )
        disassembler = architecture.disassembler.select(selections.disassembler)()
        compiler = self._build_compiler(
            target,
            config,
            compiler=compiler,
            image=image,
            symbol_resolver=symbol_resolver,
            assembler=assembler,
            disassembler=disassembler,
        )
        utils = architecture.utilities.select(selections.utilities)(
            architecture=archinfo,
            assembler=assembler,
            disassembler=disassembler,
            compiler=compiler,
            binary_analyzer=analyzer,
            allocation_manager=allocation_manager,
            image=image,
        )
        return BuiltComponents(
            archinfo=archinfo,
            binary_analyzer=analyzer,
            image=image,
            allocation_manager=allocation_manager,
            symbol_resolver=symbol_resolver,
            assembler=assembler,
            disassembler=disassembler,
            compiler=compiler,
            utils=utils,
            placement_strategy=placement,
            load_model=load_model,
        )

    @staticmethod
    def _build_analyzer(
        binary_path: Path,
        target: TargetDefinition,
        config: TargetConfig,
        image: ImageBackend,
        *,
        resource_stack: ExitStack,
        binary_analyzer: BinaryAnalyzer | None,
    ) -> BinaryAnalyzer:
        if binary_analyzer is not None:
            return binary_analyzer
        analyzer_builder = config.overrides.binary_analyzer
        if analyzer_builder is None:
            analyzer_builder = target.analyzer.select(config.selections.binary_analyzer)
        analyzer = analyzer_builder(str(binary_path), image)
        if isinstance(analyzer, AbstractContextManager):
            return resource_stack.enter_context(analyzer)
        return analyzer

    @staticmethod
    def _build_assembler(
        target: TargetDefinition,
        config: TargetConfig,
        symbol_resolver: SymbolResolver,
        *,
        assembly_backend: AssemblyBackend | None,
    ) -> Assembler:
        if assembly_backend is not None:
            return Assembler(symbol_resolver, assembly_backend)
        return target.architecture.assembler.select(config.selections.assembler)(symbol_resolver)

    @staticmethod
    def _build_compiler(
        target: TargetDefinition,
        config: TargetConfig,
        *,
        compiler: Compiler | None,
        image: ImageBackend,
        symbol_resolver: SymbolResolver,
        assembler: Assembler,
        disassembler: Disassembler,
    ) -> Compiler:
        if compiler is not None:
            return compiler
        return target.architecture.compiler.select(config.selections.compiler)(
            architecture=target.architecture.info,
            image=image,
            symbol_resolver=symbol_resolver,
            assembler=assembler,
            disassembler=disassembler,
        )

    @staticmethod
    def _build_placement(
        target: TargetDefinition, config: TargetConfig
    ) -> PlacementStrategy | None:
        placement = target.image.placement
        selected = config.selections.placement
        override = config.overrides.placement
        if placement is None:
            if selected is not None or override is not None:
                raise ValueError(f"Target {target.name!r} has no placement strategy")
            return None
        return override if override is not None else placement.select(selected)()

    @staticmethod
    def _build_load_model(target: TargetDefinition, config: TargetConfig) -> LoadModel | None:
        selected = config.selections.load_model
        override = config.overrides.load_model
        if target.runtime is None:
            if selected is not None or override is not None:
                raise ValueError(f"Target {target.name!r} has no runtime load model")
            return None
        return override if override is not None else target.runtime.load_model.select(selected)()
