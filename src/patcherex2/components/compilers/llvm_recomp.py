from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from subprocess import CalledProcessError
from typing import Any, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.compilers import ObjectCompiler

logger = logging.getLogger(__name__)


@final
class LLVMRecompObjectCompiler(ObjectCompiler):
    """Produce relocatable objects through the LLVM recompilation pipeline."""

    _NON_PREEMPTIBLE_SOURCE_HEADER = "#pragma GCC visibility push(hidden)\n"
    preserve_none = False

    def __init__(
        self,
        version: int,
        compiler_flags: Sequence[str],
        position_independent: bool,
        non_pic_compiler_flags: Sequence[str] = (),
        *,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.version = version
        self.compiler = f"clang-{version}"
        self.linker = f"ld.lld-{version}"
        self.compiler_flags: tuple[str, ...] = tuple(compiler_flags)
        self.position_independent: bool = position_independent
        self.non_pic_compiler_flags: tuple[str, ...] = tuple(non_pic_compiler_flags)
        self.assets_path: str | Path = asset_resolver.resolve("llvm_recomp")
        self.command_runner = command_runner

    @override
    def compile_object(
        self,
        code: str,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Compile C through the recompiler passes into a relocatable object."""
        if extension != ".c":
            raise ValueError("LLVM recompilation only accepts C source")
        if self.position_independent:
            code = self._NON_PREEMPTIBLE_SOURCE_HEADER + code
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "code.c")
            llvm_path = os.path.join(directory, "code.ll")
            object_path = os.path.join(directory, "obj.o")
            with open(source_path, "w") as stream:
                stream.write(code)
            self._compile_llvm(source_path, llvm_path, extra_compiler_flags)
            if kwargs.get("dso_local_fix"):
                self._force_dso_local(llvm_path)
            stack_layout = kwargs.get("stacklayout")
            if stack_layout is None:
                self._compile_object(llvm_path, object_path)
            else:
                self._compile_object_with_stack_layout(
                    llvm_path,
                    object_path,
                    directory,
                    stack_layout,
                )
            with open(object_path, "rb") as stream:
                return stream.read()

    def _compile_llvm(
        self,
        source_path: str,
        llvm_path: str,
        extra_compiler_flags: list[str] | None,
    ) -> None:
        self._run(
            [
                self.compiler,
                *self.compiler_flags,
                *self.position_flags(),
                *(extra_compiler_flags or ()),
                "-Wno-incompatible-library-redeclaration",
                "-S",
                "-w",
                "-emit-llvm",
                "-g",
                "-o",
                llvm_path,
                source_path,
                "-I/usr/lib/clang/15/include",
            ]
        )

    def _force_dso_local(self, llvm_path: str) -> None:
        self._run(
            [
                f"opt-{self.version}",
                f"-load-pass-plugin={self._recompiler_library}",
                "-passes=force-dso-local",
                "-S",
                llvm_path,
                "-o",
                llvm_path,
            ]
        )

    def _compile_object(self, llvm_path: str, object_path: str) -> None:
        self._run(
            [
                f"llc-{self.version}",
                "-o",
                object_path,
                llvm_path,
                self._relocation_flag,
                "--filetype=obj",
            ]
        )

    def _compile_object_with_stack_layout(
        self,
        llvm_path: str,
        object_path: str,
        directory: str,
        stack_layout: Any,
    ) -> None:
        layout_path = os.path.join(directory, "stacklayout.json")
        first_mir_path = os.path.join(directory, "code.mir")
        second_mir_path = os.path.join(directory, "code.2.mir")
        with open(layout_path, "w") as stream:
            json.dump(stack_layout, stream)
        self._run(
            [
                f"llc-{self.version}",
                "-stop-before=prologepilog",
                llvm_path,
                "-o",
                first_mir_path,
                self._relocation_flag,
            ]
        )
        self._run(
            [
                f"llc-{self.version}",
                "-load",
                self._recompiler_library,
                "-run-pass=updated-prologepilog",
                f"-stkloc={layout_path}",
                "-o",
                second_mir_path,
                first_mir_path,
                self._relocation_flag,
            ]
        )
        self._run(
            [
                f"llc-{self.version}",
                "-start-after=prologepilog",
                "-o",
                object_path,
                second_mir_path,
                self._relocation_flag,
                "--filetype=obj",
            ]
        )

    @property
    def _recompiler_library(self) -> str:
        return os.path.join(self.assets_path, "libRecompiler.so")

    @property
    def _relocation_flag(self) -> str:
        model = "pic" if self.position_independent else "static"
        return f"-relocation-model={model}"

    def position_flags(self) -> tuple[str, ...]:
        """Return flags appropriate for the target's position model."""
        if self.position_independent:
            return ()
        return ("-fno-pic", *self.non_pic_compiler_flags)

    def _run(self, args: list[str]) -> None:
        try:
            self.command_runner.run(args)
        except CalledProcessError as error:
            logger.error(error.stderr.decode("utf-8"))
            raise
