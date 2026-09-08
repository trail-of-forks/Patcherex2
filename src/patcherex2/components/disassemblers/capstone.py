from __future__ import annotations

from patcherex2.components.disassemblers.capstone_api import create_capstone
from patcherex2.components.disassemblers.disassembler import Disassembler, Instruction


class Capstone(Disassembler):
    def __init__(self, arch: int, mode: int) -> None:
        self.cs = create_capstone(arch, mode)

    def disassemble(self, input: bytes, base=0, **kwargs) -> list[Instruction]:
        cs_insns = self.cs.disasm(input, base)
        result: list[Instruction] = []
        for insn in cs_insns:
            result.append(
                {
                    "address": insn.address,
                    "size": insn.size,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                }
            )
        return result
