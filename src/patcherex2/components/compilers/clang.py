from collections.abc import Sequence
from typing import final

from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.compilers.command import CommandObjectCompiler


@final
class ClangObjectCompiler(CommandObjectCompiler):
    """Compile objects with a versioned Clang and its matching capabilities."""

    def __init__(
        self,
        version: int,
        compiler_flags: Sequence[str],
        position_independent: bool,
        non_pic_compiler_flags: Sequence[str],
        *,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.version = version
        self.linker = f"ld.lld-{version}"
        super().__init__(
            f"clang-{version}",
            compiler_flags,
            position_independent,
            non_pic_compiler_flags,
            preserve_none=version >= 19,
            command_runner=command_runner,
        )
