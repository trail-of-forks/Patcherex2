from __future__ import annotations

from collections.abc import Sequence
from typing import final

from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.compilers.command import CommandObjectCompiler


@final
class BccObjectCompiler(CommandObjectCompiler):
    """Compile SPARC objects with the bundled BCC toolchain configuration."""

    def __init__(
        self,
        position_independent: bool,
        non_pic_compiler_flags: Sequence[str] = (),
        *,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        assets_path = asset_resolver.resolve("bcc")
        self.linker = str(assets_path / "sparc-gaisler-elf-ld")
        super().__init__(
            str(assets_path / "sparc-gaisler-elf-gcc"),
            ["-qbsp=gr712rc", "-mcpu=leon3", "-mfix-gr712rc"],
            position_independent,
            non_pic_compiler_flags,
            command_runner=command_runner,
        )
