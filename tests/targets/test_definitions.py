from typing import Any

import pytest
from pydantic import ValidationError

from patcherex2 import PatchSession
from patcherex2.components.compilers import CompilerPipeline
from patcherex2.components.compilers.clang import ClangObjectCompiler
from patcherex2.targets import (
    ELF_AMD64_LINUX,
    ComponentFactory,
    ComponentOverrides,
    ComponentSelections,
    TargetConfig,
)
from tests.support.paths import TEST_BINARIES

BINARIES = TEST_BINARIES


def test_target_definition_is_frozen():
    with pytest.raises(ValidationError, match="Instance is frozen"):
        ELF_AMD64_LINUX.__setattr__("name", "changed")


def test_nested_architecture_info_is_frozen():
    with pytest.raises(ValidationError, match="Instance is frozen"):
        ELF_AMD64_LINUX.architecture.info.__setattr__("bits", 32)


def test_component_factory_reports_available_choices():
    factory = ComponentFactory(
        role="test component",
        default="one",
        choices={"one": lambda: 1},
    )

    with pytest.raises(ValueError, match="available: one"):
        factory.select("two")


def test_component_factory_selects_default_builder():
    factory = ComponentFactory(
        role="test component",
        default="one",
        choices={"one": lambda: 1},
    )

    assert factory.select(None)() == 1


@pytest.mark.parametrize(
    "field", ["image", "binary_analyzer", "allocation_manager", "placement", "load_model"]
)
@pytest.mark.parametrize("value", [0, False, "", {}])
def test_overrides_reject_falsey_non_components(field, value):
    with pytest.raises(ValidationError):
        ComponentOverrides(**{field: value})


def test_raw_image_config_cannot_be_mistaken_for_a_placement_policy():
    from patcherex2.targets import ArmRawImageConfig

    with pytest.raises(ValidationError):
        ComponentOverrides.model_validate({"placement": ArmRawImageConfig(image_base=0)})


def test_selection_and_override_for_the_same_role_are_rejected():
    from patcherex2.targets import ArmRawImageConfig

    with pytest.raises(ValidationError, match="selection or an override"):
        TargetConfig(
            selections=ComponentSelections(image="raw"),
            overrides=ComponentOverrides(image=ArmRawImageConfig(image_base=0).build),
        )


def test_models_require_keyword_arguments():
    model_type: Any = TargetConfig

    with pytest.raises(TypeError, match="positional"):
        model_type(ComponentSelections())


def test_patch_session_materializes_selected_component():
    with PatchSession.load_binary(
        BINARIES / "amd64/printf_nopie",
        target=ELF_AMD64_LINUX,
        config=TargetConfig(selections=ComponentSelections(compiler="clang19")),
    ) as patcher:
        assert patcher.target is ELF_AMD64_LINUX
        assert isinstance(patcher.compiler, CompilerPipeline)
        assert isinstance(patcher.compiler.object_compiler, ClangObjectCompiler)
        assert patcher.compiler.object_compiler.compiler == "clang-19"
