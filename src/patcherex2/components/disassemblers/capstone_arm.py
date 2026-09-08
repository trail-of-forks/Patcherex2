from __future__ import annotations

import capstone

from patcherex2.components.disassemblers.capstone_api import create_capstone
from patcherex2.components.disassemblers.disassembler import Disassembler, Instruction


class CapstoneArm(Disassembler):
    def __init__(self) -> None:
        self.cs_arm = create_capstone(
            capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN
        )
        self.cs_thumb = create_capstone(
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def disassemble(self, input: bytes, base=0, is_thumb=False, **kwargs) -> list[Instruction]:
        cs = self.cs_thumb if is_thumb else self.cs_arm
        cs_insns = cs.disasm(input, base)
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
