# Adding New Target Support

Targets are immutable declarations, not subclasses. A `TargetDefinition` composes
independent profiles:

- `ArchitectureProfile` contains immutable architecture information and selects the
  assembler, disassembler, compiler, and architecture utilities.
- `ImageProfile` selects the file-format backend and allocation policy. Placement is
  optional because ordinary ELF images can derive and extend their mapped ranges,
  while bare-metal images generally need caller-supplied ranges.
- `RuntimeProfile` is optional and describes runtime initialization such as copying
  initialized data from flash into RAM.
- The target definition selects a binary analyzer appropriate for the complete
  combination.

`ComponentBuilder` is the only layer that turns these declarations into live
objects. It constructs them in dependency order and passes dependencies explicitly.

Architecture facts are `ArchitectureInfo` values, not component implementations.
Standard declarations such as `AMD64`, `ARM`, and `MIPS` live in their corresponding
`patcherex2.components.arch` modules. A profile stores one directly in its `info` field;
there is no architecture factory, selection, or constructor-options boundary.

## Defining a Target

Reuse existing profiles whenever the architecture or image mechanics are unchanged:

```python
from patcherex2.targets.profiles import (
    AMD64_LINUX,
    ELF_IMAGE,
    standard_analyzer_factory,
)
from patcherex2.targets.target import ImageProfile, TargetDefinition

MY_ELF_AMD64 = TargetDefinition(
    name="my-elf-amd64",
    architecture=AMD64_LINUX,
    image=ELF_IMAGE,
    analyzer=standard_analyzer_factory(),
)
```

Create a new component implementation only when its behavior is genuinely new. The
component interfaces remain ABCs or protocols; `ComponentFactory` declares the named
implementations available for one role:

```python
from patcherex2.models import FrozenPatcherexModel
from patcherex2.targets.target import ComponentFactory


class MyImageConfig(FrozenPatcherexModel):
    image_base: int

    def build(self, binary_path: str) -> MyImageBackend:
        return MyImageBackend(binary_path, image_base=self.image_base)


configured_image = MyImageConfig(image_base=0x1000)


MY_IMAGE = ImageProfile(
    name="my-image",
    backend=ComponentFactory(
        role="image backend",
        default="my-backend",
        choices={"my-backend": configured_image.build},
    ),
    allocator=ELF_IMAGE.allocator,
)
```

`ComponentFactory.select()` returns the selected builder. Each component role defines
the builder's callable protocol, including only runtime dependencies. Configuration
is already bound by the caller. Keeping builders next to the profile makes composition visible
without adding another inheritance hierarchy.

## Selecting a Target

Callers must select a target explicitly:

```python
from patcherex2 import PatchSession

with PatchSession.load_binary("/path/to/binary", target=MY_ELF_AMD64) as session:
    ...
```

Patcherex2 does not infer a concrete target from the input. ELF headers can identify
the file format and architecture, but cannot reliably distinguish a hosted executable
from a bare-metal image. Raw images provide even less identifying information.

## Configuration

Selections and configured overrides are grouped in `TargetConfig`. Bind configuration
inside typed builders before passing them to the component graph. Builders receive
only their declared runtime dependencies; placement and load policies are injected directly:

```python
from patcherex2.targets import ComponentOverrides, ComponentSelections, TargetConfig
from patcherex2.components.binary_analyzer.ghidra import GhidraAnalyzer
from patcherex2.components.image import ImageBackend


def configured_ghidra(binary_path: str, image: ImageBackend):
    return GhidraAnalyzer.load_binary(binary_path, language="x86:LE:64:default")


with PatchSession.load_binary(
    "/path/to/binary",
    target=MY_ELF_AMD64,
    config=TargetConfig(
        selections=ComponentSelections(
            compiler="clang19",
        ),
        overrides=ComponentOverrides(
            binary_analyzer=configured_ghidra,
        ),
    ),
) as session:
    ...
```

The analyzer returned by this builder is context-managed by the session. An analyzer
passed directly to `load_binary(binary_analyzer=...)` remains owned by its caller.

## Borrowing an Existing Analyzer

Pass an already-live `BinaryAnalyzer` implementation when the caller owns an open
Ghidra, IDA, angr, or other analysis session:

```python
with PatchSession.load_binary(
    "/path/to/binary",
    target=MY_ELF_AMD64,
    binary_analyzer=already_open_analyzer,
) as session:
    session.apply_patches()
```

The injected analyzer bypasses the target's analyzer factory. `PatchSession` borrows
it: exiting the patch session does not enter, close, or otherwise change the lifetime
of the analyzer. The caller remains responsible for closing it. A caller can likewise
inject a `Compiler` or `AssemblyBackend` through the typed `compiler=` and
`assembly_backend=` parameters; these bypass their corresponding target factories.

### Configuring an angr CFG

`AngrAnalyzer.load_binary(binary_path, angr_kwargs=..., angr_cfg_kwargs=...)`
constructs the project and CFG before yielding. Pass CFG options before entering
that context; the analyzer has no mutable `angr_cfg_kwargs` attribute, and accessing
`analyzer.cfg` does not trigger analysis.

If the scope depends on loader metadata, pass a callback as `angr_cfg_kwargs`.
It receives the loaded project exactly once and returns options before CFG
construction. The returned mapping is copied, and `normalize` defaults to `True`
unless explicitly set. If the callback raises, the exception propagates without
building a CFG or yielding an analyzer; there is no whole-program fallback.

Use a configured analyzer builder to let the session manage construction and
ownership. In this example, `resolve_function_scope` is caller-provided logic that
returns loaded addresses `(start, end)`, with an exclusive end, using the project's
loader and the caller's desired function:

```python
from collections.abc import Mapping
from typing import Any

from patcherex2.components.binary_analyzer.angr import AngrAnalyzer, AngrProjectApi
from patcherex2.components.image import ImageBackend
from patcherex2.targets import ComponentOverrides, TargetConfig


def resolve_cfg_options(project: AngrProjectApi) -> Mapping[str, Any]:
    start, end = resolve_function_scope(project)
    return {"regions": [(start, end)], "function_starts": [start]}


def configured_analyzer(binary_path: str, image: ImageBackend):
    return AngrAnalyzer.load_binary(binary_path, angr_cfg_kwargs=resolve_cfg_options)


config = TargetConfig(
    overrides=ComponentOverrides(binary_analyzer=configured_analyzer),
)
with PatchSession.load_binary(binary_path, target=MY_ELF_AMD64, config=config) as session:
    ...
```

Include any other CFG options required by your target in the returned mapping.
Static mappings remain supported when loaded addresses are already known. Creating
an analyzer does not defer analysis until its first `cfg` access: resolve the scope
before construction to avoid an initial whole-program CFG.
