import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from patcherex2.components.assembler.bcc import BccAssemblyBackend
from patcherex2.components.assembler.ppc_vle import PpcVleAssemblyBackend
from patcherex2.components.assets import AssetResolver
from patcherex2.components.command_runner import CommandRunner
from patcherex2.components.compilers import ObjectCompiler
from patcherex2.components.compilers.bcc import BccObjectCompiler
from patcherex2.components.compilers.clang import ClangObjectCompiler
from patcherex2.components.compilers.llvm_recomp import LLVMRecompObjectCompiler
from patcherex2.components.compilers.ppc_vle import PpcVleObjectCompiler
from patcherex2.components.disassemblers.ppc_vle import PpcVle


class FakeAssetResolver:
    """Resolve test toolchains without touching the package asset store."""

    def resolve(self, name: str) -> Path:
        directory = "ppc-vle" if name == "ppc_vle" else name
        return Path("/toolchains") / directory


class FakeCommandRunner:
    def __init__(
        self,
        run: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]],
    ) -> None:
        self._run = run

    def run(self, command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        return self._run(command)


def test_command_compiler_recompiles_identical_source():
    outputs = iter((b"first object", b"second object"))
    commands = []

    def compile_to_object(command):
        commands.append(tuple(command))
        Path(command[-1]).write_bytes(next(outputs))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    runner: CommandRunner = FakeCommandRunner(compile_to_object)
    compiler = ClangObjectCompiler(
        19,
        ["--target=x86_64"],
        False,
        (),
        command_runner=runner,
    )

    first = compiler.compile_object("int value;")
    second = compiler.compile_object("int value;")

    assert first == b"first object"
    assert second == b"second object"
    assert len(commands) == 2


def test_clang_constrains_versioned_commands_and_capabilities():
    compiler = ClangObjectCompiler(19, ["--target=x86_64"], False, ())

    assert isinstance(compiler, ObjectCompiler)
    assert compiler.compiler == "clang-19"
    assert compiler.linker == "ld.lld-19"
    assert compiler.preserve_none


def test_bcc_constrains_bundled_commands_and_required_flags():
    resolver: AssetResolver = FakeAssetResolver()
    compiler = BccObjectCompiler(False, asset_resolver=resolver)

    assert compiler.compiler == "/toolchains/bcc/sparc-gaisler-elf-gcc"
    assert compiler.linker == "/toolchains/bcc/sparc-gaisler-elf-ld"
    assert compiler.compiler_flags == (
        "-qbsp=gr712rc",
        "-mcpu=leon3",
        "-mfix-gr712rc",
    )


def test_ppc_vle_constrains_bundled_commands_and_required_flags():
    resolver: AssetResolver = FakeAssetResolver()
    compiler = PpcVleObjectCompiler(False, asset_resolver=resolver)

    assert compiler.compiler == "/toolchains/ppc-vle/powerpc-eabivle-gcc"
    assert compiler.linker == "/toolchains/ppc-vle/powerpc-eabivle-ld"
    assert compiler.compiler_flags == ("-mno-vle",)


def test_llvm_recomp_constrains_versioned_commands():
    resolver: AssetResolver = FakeAssetResolver()
    compiler = LLVMRecompObjectCompiler(
        15,
        ["--target=x86_64"],
        False,
        asset_resolver=resolver,
    )

    assert isinstance(compiler, ObjectCompiler)
    assert compiler.compiler == "clang-15"
    assert compiler.linker == "ld.lld-15"
    assert compiler.position_flags() == ("-fno-pic",)


@pytest.mark.parametrize(
    ("tool_type", "expected_path"),
    [
        (BccAssemblyBackend, Path("/toolchains/bcc")),
        (PpcVleAssemblyBackend, Path("/toolchains/ppc-vle")),
        (PpcVle, Path("/toolchains/ppc-vle")),
    ],
)
def test_bundled_assembly_tools_use_injected_asset_resolver(tool_type, expected_path):
    resolver: AssetResolver = FakeAssetResolver()

    assert tool_type(resolver).assets_path == expected_path
