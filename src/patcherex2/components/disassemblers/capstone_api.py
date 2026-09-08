from collections.abc import Iterable
from typing import Protocol, cast

import capstone


class CapstoneInstruction(Protocol):
    @property
    def address(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def mnemonic(self) -> str: ...

    @property
    def op_str(self) -> str: ...


class CapstoneApi(Protocol):
    """The Capstone operations used by our disassemblers."""

    syntax: int

    def disasm(self, code: bytes, offset: int, /) -> Iterable[CapstoneInstruction]: ...


def create_capstone(arch: int, mode: int) -> CapstoneApi:
    """Adapt Capstone's dynamically typed native binding to our consumed API."""
    return cast(CapstoneApi, capstone.Cs(arch, mode))
