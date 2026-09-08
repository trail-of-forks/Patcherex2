from __future__ import annotations

import logging
import os
import sys
import tempfile
from collections.abc import Sequence
from subprocess import CalledProcessError
from typing import Any

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.command_runner import (
    DEFAULT_COMMAND_RUNNER,
    CommandRunner,
)
from patcherex2.components.compilers import ObjectCompiler

logger = logging.getLogger(__name__)


class CommandObjectCompiler(ObjectCompiler):
    """Produce relocatable objects with a conventional compiler command."""

    _NON_PREEMPTIBLE_SOURCE_HEADER = "#pragma GCC visibility push(hidden)\n"

    def __init__(
        self,
        compiler: str,
        compiler_flags: Sequence[str],
        position_independent: bool,
        non_pic_compiler_flags: Sequence[str] = (),
        preserve_none: bool = False,
        *,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.compiler: str = compiler
        self.compiler_flags: tuple[str, ...] = tuple(compiler_flags)
        self.position_independent: bool = position_independent
        self.non_pic_compiler_flags: tuple[str, ...] = tuple(non_pic_compiler_flags)
        self.preserve_none = preserve_none
        self.command_runner = command_runner

    @override
    def compile_object(
        self,
        code: str,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Compile source into a relocatable object."""
        del kwargs
        if self.position_independent:
            code = self._NON_PREEMPTIBLE_SOURCE_HEADER + code
        flags = (
            *self.compiler_flags,
            *self.position_flags(),
            *tuple(extra_compiler_flags or ()),
        )
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, f"code{extension}")
            object_path = os.path.join(directory, "obj.o")
            with open(source_path, "w") as stream:
                stream.write(code)
            try:
                self.command_runner.run(
                    [self.compiler, *flags, "-c", source_path, "-o", object_path]
                )
            except CalledProcessError as error:
                logger.error(error.stderr.decode("utf-8"))
                raise
            with open(object_path, "rb") as stream:
                object_bytes = stream.read()
        return object_bytes

    def position_flags(self) -> tuple[str, ...]:
        """Return flags appropriate for the target's position model."""
        if self.position_independent:
            return ()
        return ("-fno-pic", *self.non_pic_compiler_flags)
