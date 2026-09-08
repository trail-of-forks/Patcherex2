from __future__ import annotations

from typing import TypedDict


class Instruction(TypedDict):
    address: int
    size: int
    mnemonic: str
    op_str: str


class Disassembler:
    def disassemble(self, input: bytes, base=0, **kwargs) -> list[Instruction]:
        raise NotImplementedError()

    def to_asm_string(self, insn: Instruction) -> str:
        return "{} {}".format(insn["mnemonic"], insn["op_str"])
