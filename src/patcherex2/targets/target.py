from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Annotated, Generic, Protocol, TypeAlias, TypeVar, runtime_checkable

from pydantic import Field, SkipValidation, model_validator
from typing_extensions import Self

from patcherex2.components.allocation_manager import AllocationManager
from patcherex2.components.arch import ArchitectureInfo
from patcherex2.components.assembler import Assembler
from patcherex2.components.binary_analyzer import BinaryAnalyzer
from patcherex2.components.compilers import Compiler
from patcherex2.components.disassemblers.disassembler import Disassembler
from patcherex2.components.image import ImageBackend
from patcherex2.components.load_models import LoadModel
from patcherex2.components.placement_strategies import PlacementStrategy
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.components.utils.utils import Utils
from patcherex2.models import FrozenPatcherexModel

BuilderT_co = TypeVar("BuilderT_co", covariant=True)
AnalyzerResult: TypeAlias = BinaryAnalyzer | AbstractContextManager[BinaryAnalyzer]


class AssemblerBuilder(Protocol):
    """Construct an assembler from its runtime dependency."""

    def __call__(self, symbol_resolver: SymbolResolver, /) -> Assembler: ...


class CompilerBuilder(Protocol):
    """Construct a compiler from the materialized component graph."""

    def __call__(
        self,
        *,
        architecture: ArchitectureInfo,
        image: ImageBackend,
        symbol_resolver: SymbolResolver,
        assembler: Assembler,
        disassembler: Disassembler,
    ) -> Compiler: ...


class DisassemblerBuilder(Protocol):
    """Construct a disassembler."""

    def __call__(self) -> Disassembler: ...


class UtilsBuilder(Protocol):
    """Construct utilities from the materialized component graph."""

    def __call__(
        self,
        *,
        architecture: ArchitectureInfo,
        assembler: Assembler,
        disassembler: Disassembler,
        compiler: Compiler,
        binary_analyzer: BinaryAnalyzer,
        allocation_manager: AllocationManager,
        image: ImageBackend,
    ) -> Utils: ...


@runtime_checkable
class ImageBackendBuilder(Protocol):
    """Construct an image backend without additional configuration."""

    def __call__(self, binary_path: str, /) -> ImageBackend: ...


@runtime_checkable
class AllocationManagerBuilder(Protocol):
    """Construct an allocation manager without additional configuration."""

    def __call__(
        self, binary_analyzer: BinaryAnalyzer, image: ImageBackend, /
    ) -> AllocationManager: ...


@runtime_checkable
class BinaryAnalyzerBuilder(Protocol):
    """Construct a binary analyzer without additional configuration."""

    def __call__(self, binary_path: str, image: ImageBackend, /) -> AnalyzerResult: ...


class PlacementStrategyBuilder(Protocol):
    """Construct a placement strategy from target-specific configuration."""

    def __call__(self) -> PlacementStrategy: ...


class LoadModelBuilder(Protocol):
    """Construct a load model from target-specific configuration."""

    def __call__(self) -> LoadModel: ...


class ComponentFactory(FrozenPatcherexModel, Generic[BuilderT_co]):
    """Named implementations available for one component role."""

    role: Annotated[str, Field(min_length=1)]
    default: Annotated[str, Field(min_length=1)]
    choices: Mapping[str, SkipValidation[BuilderT_co]]

    @model_validator(mode="after")
    def validate_default(self) -> Self:
        if self.default not in self.choices:
            raise ValueError(
                f"Default {self.role} {self.default!r} is not one of {', '.join(sorted(self.choices))}"
            )
        return self

    def select(self, selected: str | None) -> BuilderT_co:
        """Return the selected component builder."""
        name = self.default if selected is None else selected
        try:
            return self.choices[name]
        except KeyError as error:
            available = ", ".join(sorted(self.choices))
            raise ValueError(f"Unsupported {self.role} {name!r}; available: {available}") from error


class ArchitectureProfile(FrozenPatcherexModel):
    """Architecture-dependent component declarations."""

    name: Annotated[str, Field(min_length=1)]
    info: ArchitectureInfo
    assembler: ComponentFactory[AssemblerBuilder]
    compiler: ComponentFactory[CompilerBuilder]
    disassembler: ComponentFactory[DisassemblerBuilder]
    utilities: ComponentFactory[UtilsBuilder]


class ImageProfile(FrozenPatcherexModel):
    """Image rewriting and allocation policy for a concrete file format."""

    name: Annotated[str, Field(min_length=1)]
    backend: ComponentFactory[ImageBackendBuilder]
    allocator: ComponentFactory[AllocationManagerBuilder]
    placement: ComponentFactory[PlacementStrategyBuilder] | None = None


class RuntimeProfile(FrozenPatcherexModel):
    """Optional policy describing how the image is materialized in memory."""

    name: Annotated[str, Field(min_length=1)]
    load_model: ComponentFactory[LoadModelBuilder]


class TargetDefinition(FrozenPatcherexModel):
    """Immutable composition of architecture, image, analysis, and runtime."""

    name: Annotated[str, Field(min_length=1)]
    architecture: ArchitectureProfile
    image: ImageProfile
    analyzer: ComponentFactory[BinaryAnalyzerBuilder]
    runtime: RuntimeProfile | None = None


class ComponentSelections(FrozenPatcherexModel):
    """Optional implementation selections; profile defaults fill omitted fields."""

    assembler: str | None = None
    compiler: str | None = None
    disassembler: str | None = None
    binary_analyzer: str | None = None
    image: str | None = None
    allocation_manager: str | None = None
    utilities: str | None = None
    placement: str | None = None
    load_model: str | None = None


class ComponentOverrides(FrozenPatcherexModel):
    """Configured builders and policies supplied by the caller.

    Bind configuration in a typed constructor or closure before assembling the
    graph. Builders receive only their declared runtime dependencies.
    """

    binary_analyzer: BinaryAnalyzerBuilder | None = None
    image: ImageBackendBuilder | None = None
    allocation_manager: AllocationManagerBuilder | None = None
    placement: PlacementStrategy | None = None
    load_model: LoadModel | None = None


class TargetConfig(FrozenPatcherexModel):
    """Typed configuration used while materializing a target declaration."""

    selections: ComponentSelections = Field(default_factory=ComponentSelections)
    overrides: ComponentOverrides = Field(default_factory=ComponentOverrides)

    @model_validator(mode="after")
    def reject_conflicting_selections(self) -> Self:
        """Do not silently discard a selection when the role is overridden."""
        pairs = (
            ("image", self.selections.image, self.overrides.image),
            ("binary_analyzer", self.selections.binary_analyzer, self.overrides.binary_analyzer),
            (
                "allocation_manager",
                self.selections.allocation_manager,
                self.overrides.allocation_manager,
            ),
            ("placement", self.selections.placement, self.overrides.placement),
            ("load_model", self.selections.load_model, self.overrides.load_model),
        )
        for role, selection, override in pairs:
            if selection is not None and override is not None:
                raise ValueError(f"Specify either a {role} selection or an override, not both")
        return self
