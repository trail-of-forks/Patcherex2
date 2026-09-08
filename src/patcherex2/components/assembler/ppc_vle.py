import logging
import os
import re
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
class PpcVleAssemblyBackend(AssemblyBackend):
    """Assemble PowerPC VLE code with the bundled GNU toolchain."""

    def __init__(
        self,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.assets_path: str | Path = asset_resolver.resolve("ppc_vle")
        self.command_runner = command_runner

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        if is_thumb:
            raise ValueError("PowerPC VLE assembly does not support Thumb mode")
        code = re.subn(r"\br(\d+)\b", r"\1", code)[0]

        code = self._rewrite_branches(code, base)
        code = f".org {hex(base)}\n" + code

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(code)
            try:
                self.command_runner.run(
                    [
                        os.path.join(self.assets_path, "powerpc-eabivle-as"),
                        "-o",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "code.s"),
                    ]
                )
            except CalledProcessError as error:
                logger.error(error.stderr.decode("utf-8"))
                raise
            try:
                self.command_runner.run(
                    [
                        os.path.join(self.assets_path, "powerpc-eabivle-objcopy"),
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

    def _rewrite_branches(self, code: str, base: int) -> str:
        branch_instructions = {}
        instruction_count = 0
        for line in code.splitlines():
            line = line.strip()
            if line.startswith((".", "#")) or line == "" or line.endswith(":"):
                continue
            if re.match(r"b[a-z]* 0x[0-9a-fA-F]+", line):
                branch_instructions[instruction_count] = line
            instruction_count += 1

        for index, instruction in branch_instructions.items():
            mnemonic, destination = instruction.split(" ")
            branch_instructions[index] = (
                f"{mnemonic} {hex(int(destination, 16) - base - 4 * index)}"
            )

        instruction_count = 0
        lines = code.splitlines()
        for line_number, line in enumerate(lines):
            if line.startswith((".", "#")) or line == "" or line.endswith(":"):
                continue
            if instruction_count in branch_instructions:
                lines[line_number] = branch_instructions[instruction_count]
            instruction_count += 1
        return "\n".join(lines)
