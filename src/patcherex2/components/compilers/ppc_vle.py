from __future__ import annotations

from collections.abc import Sequence
from typing import final

from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.compilers.command import CommandObjectCompiler


@final
class PpcVleObjectCompiler(CommandObjectCompiler):
    """Compile PowerPC VLE objects with the bundled VLE toolchain."""

    def __init__(
        self,
        position_independent: bool,
        non_pic_compiler_flags: Sequence[str] = (),
        *,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        assets_path = asset_resolver.resolve("ppc_vle")
        self.linker = str(assets_path / "powerpc-eabivle-ld")
        super().__init__(
            str(assets_path / "powerpc-eabivle-gcc"),
            ["-mno-vle"],
            position_independent,
            non_pic_compiler_flags,
            command_runner=command_runner,
        )
