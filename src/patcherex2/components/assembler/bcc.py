import logging
import os
import sys
import tempfile
from pathlib import Path
from subprocess import CalledProcessError
from typing import final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import AssemblyBackend
from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner

logger = logging.getLogger(__name__)


@final
class BccAssemblyBackend(AssemblyBackend):
    """Assemble SPARC code with the bundled BCC toolchain."""

    def __init__(
        self,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.assets_path: str | Path = asset_resolver.resolve("bcc")
        self.command_runner = command_runner

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        if is_thumb:
            raise ValueError("BCC SPARC assembly does not support Thumb mode")
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(f".org {hex(base)}\n")
                f.write(code)
            try:
                self.command_runner.run(
                    [
                        os.path.join(self.assets_path, "sparc-gaisler-elf-as"),
                        "-Aleon",
                        os.path.join(td, "code.s"),
                        "-o",
                        os.path.join(td, "obj.o"),
                    ]
                )
            except CalledProcessError as error:
                logger.error(error.stderr.decode("utf-8"))
                raise
            try:
                self.command_runner.run(
                    [
                        os.path.join(self.assets_path, "sparc-gaisler-elf-objcopy"),
                        "-O",
                        "binary",
                        "-j",
                        ".text",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "obj.bin"),
                    ]
                )
            except CalledProcessError as error:
                logger.error(error.stderr.decode("utf-8"))
                raise
            with open(os.path.join(td, "obj.bin"), "rb") as f:
                if base != 0:
                    f.seek(base)
                binary = f.read()
                logger.debug(f"Assembled bytes: {bytes(binary).hex()}")
                return bytes(binary)
