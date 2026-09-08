from __future__ import annotations

import logging
import os
import re
import tempfile
from subprocess import CalledProcessError

from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.components.command_runner import DEFAULT_COMMAND_RUNNER, CommandRunner
from patcherex2.components.disassemblers.disassembler import Disassembler, Instruction

logger = logging.getLogger(__name__)


class PpcVle(Disassembler):
    def __init__(
        self,
        asset_resolver: AssetResolver = DEFAULT_ASSET_RESOLVER,
        command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
    ) -> None:
        self.assets_path = asset_resolver.resolve("ppc_vle")
        self.command_runner = command_runner

    def disassemble(self, input: bytes, base=0, **kwargs) -> list[Instruction]:
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.bin"), "wb") as f:
                f.write(input)

            try:
                proc = self.command_runner.run(
                    [
                        os.path.join(self.assets_path, "powerpc-eabivle-objdump"),
                        "-D",
                        "-b",
                        "binary",
                        f"--adjust-vma={hex(base)}",
                        "-m",
                        "powerpc:common",
                        "-EB",
                        os.path.join(td, "code.bin"),
                    ]
                )
                # skip objdump's 7 header lines
                str_result = "\n".join(proc.stdout.decode("utf-8").splitlines()[7:])
            except CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise

        result: list[Instruction] = []
        for line in str_result.splitlines():
            m = re.match(
                r"\s+(?P<address>[0-9a-f]+):\s+"
                r"(?P<bytes>([0-9a-f]{2}\s)+)\s+"
                r"(?P<mnemonic>.+?)\s+(?P<op_str>.+?)$",
                line,
            )
            if m:
                instr = m.groupdict()
                result.append(
                    Instruction(
                        address=int(instr["address"], 16),
                        size=len(bytes.fromhex(instr["bytes"])),
                        mnemonic=re.sub(r"\s+", "", instr["mnemonic"]),
                        op_str=re.sub(r"\s+", "", instr["op_str"].split(";")[0]).replace(",", ", "),
                    )
                )
        return result
