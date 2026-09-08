from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from patcherex2 import PatchSession
from patcherex2.components.compilers import (
    CompilationEngine,
    CompilerPipeline,
    ObjectCompiler,
)
from patcherex2.components.compilers.arm import ArmCompiler
from patcherex2.components.compilers.clang import ClangObjectCompiler
from patcherex2.components.compilers.elf import ElfCompilationEngine
from patcherex2.targets import ELF_AMD64_LINUX, ELF_ARM_LINUX, ComponentFactory
from tests.support.fakes import CallbackAssemblyBackend, FakeBinaryAnalyzer, FakeCompiler
from tests.support.paths import TEST_BINARIES


def test_load_binary_requires_an_explicit_target():
    load_binary: Any = PatchSession.load_binary

    with (
        pytest.raises(TypeError, match="target"),
        load_binary(TEST_BINARIES / "amd64/printf_nopie"),
    ):
        pass


@pytest.mark.parametrize(
    "binary_path",
    [
        TEST_BINARIES / "amd64/printf_nopie",
        str(TEST_BINARIES / "amd64/printf_nopie"),
    ],
)
def test_load_binary_normalizes_path_inputs(binary_path: str | Path):
    with PatchSession.load_binary(binary_path, target=ELF_AMD64_LINUX) as session:
        assert session.binary_path == TEST_BINARIES / "amd64/printf_nopie"
        assert isinstance(session.binary_path, Path)


def build_managed_analyzer_target(events, received_images):
    @contextmanager
    def analyzer_context():
        events.append("enter")
        try:
            yield FakeBinaryAnalyzer()
        finally:
            events.append("exit")

    def build_analyzer(_binary_path, image):
        received_images.append(image)
        return analyzer_context()

    analyzer_factory = ComponentFactory(
        role="binary analyzer",
        default="managed",
        choices={"managed": build_analyzer},
    )
    return ELF_AMD64_LINUX.model_copy(update={"analyzer": analyzer_factory})


def test_session_owns_context_managed_analyzer_lifetime():
    events = []
    target = build_managed_analyzer_target(events, [])

    with PatchSession.load_binary(TEST_BINARIES / "amd64/printf_nopie", target=target) as session:
        assert events == ["enter"]
        assert not hasattr(session, "_resource_stack")

    assert events == ["enter", "exit"]


def test_load_binary_unwinds_owned_resources_when_graph_construction_fails():
    events = []
    target = build_managed_analyzer_target(events, [])

    def reject_allocator_creation(*_args, **_kwargs):
        raise RuntimeError("allocator construction failed")

    allocator_factory = ComponentFactory(
        role="allocation manager",
        default="rejected",
        choices={"rejected": reject_allocator_creation},
    )
    target = target.model_copy(
        update={"image": target.image.model_copy(update={"allocator": allocator_factory})}
    )

    with (
        pytest.raises(RuntimeError, match="allocator construction failed"),
        PatchSession.load_binary(TEST_BINARIES / "amd64/printf_nopie", target=target),
    ):
        pass

    assert events == ["enter", "exit"]


def test_analyzer_factory_receives_image_dependency():
    received_images = []
    target = build_managed_analyzer_target([], received_images)

    with PatchSession.load_binary(TEST_BINARIES / "amd64/printf_nopie", target=target) as patcher:
        assert received_images == [patcher.image]


def test_session_borrows_injected_analyzer_without_calling_target_factory():
    analyzer = FakeBinaryAnalyzer()

    def reject_analyzer_creation(*_args, **_kwargs):
        raise AssertionError("the target analyzer factory must not be called")

    analyzer_factory = ComponentFactory(
        role="binary analyzer",
        default="rejected",
        choices={"rejected": reject_analyzer_creation},
    )
    target = ELF_AMD64_LINUX.model_copy(update={"analyzer": analyzer_factory})

    with PatchSession.load_binary(
        TEST_BINARIES / "amd64/printf_nopie",
        target=target,
        binary_analyzer=analyzer,
    ) as session:
        assert session.binary_analyzer is analyzer
        assert session.allocation_manager.binary_analyzer is analyzer
        assert session.symbol_resolver.binary_analyzer is analyzer

    assert analyzer.get_all_symbols() == {}


def test_session_uses_injected_assembly_backend_behind_symbol_resolution():
    backend = CallbackAssemblyBackend(lambda *_args, **_kwargs: b"assembled")

    with PatchSession.load_binary(
        TEST_BINARIES / "amd64/printf_nopie",
        target=ELF_AMD64_LINUX,
        assembly_backend=backend,
    ) as session:
        assert session.assembler.backend is backend
        assert session.assembler.symbol_resolver is session.symbol_resolver


def test_session_borrows_injected_compiler():
    compiler = FakeCompiler()

    with PatchSession.load_binary(
        TEST_BINARIES / "amd64/printf_nopie",
        target=ELF_AMD64_LINUX,
        compiler=compiler,
    ) as session:
        assert session.compiler is compiler
        assert session.utils.compiler is compiler


@pytest.fixture(scope="module")
def patcher():
    with PatchSession.load_binary(
        TEST_BINARIES / "amd64/printf_nopie", target=ELF_AMD64_LINUX
    ) as instance:
        yield instance


def test_allocation_manager_receives_analyzer_and_image(patcher):
    assert patcher.allocation_manager.binary_analyzer is patcher.binary_analyzer
    assert patcher.allocation_manager.image is patcher.image


def test_assembler_and_compiler_receive_narrow_dependencies(patcher):
    assert patcher.assembler.symbol_resolver is patcher.symbol_resolver
    assert isinstance(patcher.compiler, CompilerPipeline)
    assert isinstance(patcher.compiler.object_compiler, ObjectCompiler)
    assert isinstance(patcher.compiler.compilation_engine, CompilationEngine)
    assert isinstance(patcher.compiler.compilation_engine, ElfCompilationEngine)
    assert isinstance(patcher.compiler.object_compiler, ClangObjectCompiler)
    assert patcher.compiler.compilation_engine.architecture is patcher.archinfo
    assert (
        patcher.compiler.object_compiler.position_independent
        is patcher.image.is_position_independent
    )
    assert patcher.compiler.compilation_engine.symbol_resolver is patcher.symbol_resolver


def test_utils_receives_all_component_dependencies(patcher):
    assert patcher.utils.allocation_manager is patcher.allocation_manager
    assert patcher.utils.image is patcher.image


def test_constructor_is_a_pure_component_injection_boundary(patcher):
    session = PatchSession(
        binary_path=patcher.binary_path,
        target=patcher.target,
        archinfo=patcher.archinfo,
        binary_analyzer=patcher.binary_analyzer,
        image=patcher.image,
        allocation_manager=patcher.allocation_manager,
        symbol_resolver=patcher.symbol_resolver,
        assembler=patcher.assembler,
        disassembler=patcher.disassembler,
        compiler=patcher.compiler,
        utils=patcher.utils,
        placement_strategy=patcher.placement_strategy,
        load_model=patcher.load_model,
    )

    assert session.binary_analyzer is patcher.binary_analyzer
    assert session.image is patcher.image
    assert session.added_functions is patcher.utils.added_functions
    assert session.symbols is patcher.symbol_resolver.patch_symbols
    assert not hasattr(session, "_resource_stack")


def test_components_do_not_retain_aggregate_session_context(patcher):
    components = (
        patcher.assembler,
        patcher.compiler,
        patcher.allocation_manager,
        patcher.binary_analyzer,
        patcher.image,
        patcher.utils,
        patcher.target,
    )
    assert all(not hasattr(component, "p") for component in components)


def test_arm_compiler_decorates_the_selected_pipeline():
    with PatchSession.load_binary(
        TEST_BINARIES / "armhf/printf_nopie", target=ELF_ARM_LINUX
    ) as patcher:
        assert isinstance(patcher.compiler, ArmCompiler)
        assert isinstance(patcher.compiler.compiler, CompilerPipeline)
        assert isinstance(
            patcher.compiler.compiler.compilation_engine,
            ElfCompilationEngine,
        )
