from __future__ import annotations

import re
from abc import ABC
from typing import Annotated, final

from pydantic import Field

from patcherex2.models import FrozenPatcherexModel

#: A name that can be substituted into patch *assembly*.
#:
#: Assembly references a symbol as ``<name>`` and the reference is replaced with
#: an address textually, before the assembler runs. The name is never parsed as
#: an identifier, so the only requirement is that it cannot be confused with the
#: delimiter or with the surrounding assembly. Names an analyzer synthesises for
#: things the binary never named are usable here.
ASM_SYMBOL_NAME_RE: re.Pattern[str] = re.compile(r"^[^\s<>]+$")

#: A name that can additionally be used from patch *C* code.
#:
#: C code reaches a symbol by declaring it ``extern``, so the compiler has to be
#: able to parse the name as an identifier. This is strictly narrower than
#: :data:`ASM_SYMBOL_NAME_RE`.
#:
#: Note the constraint comes from the language, not from linking: the name is
#: only a key matching the patch object's undefined symbol to a definition
#: supplied at link time, and it need not appear in the target's symbol table
#: at all.
C_SYMBOL_NAME_RE: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Symbol(FrozenPatcherexModel, ABC):
    """A named symbol within a target binary."""

    name: str

    @property
    def is_asm_usable(self) -> bool:
        """Whether patch assembly can reference this symbol."""
        return bool(ASM_SYMBOL_NAME_RE.match(self.name))

    @property
    def is_c_usable(self) -> bool:
        """Whether patch C code can declare this symbol ``extern``."""
        return bool(C_SYMBOL_NAME_RE.match(self.name))


@final
class MappedSymbol(Symbol):
    """A symbol with a real address in the loaded image.

    This is the only variant a patch can resolve a reference to: a name alone
    is not enough, there has to be something to point it at.
    """

    addr: Annotated[int, Field(ge=0)]

    is_stub: bool = False


@final
class ExternalSymbol(Symbol):
    """A symbol whose definition lives outside this binary.

    An imported function is the usual case: the name is known and referenced,
    but nothing here defines it, and it is not given an address until load time.

    Analyzers commonly invent an address for these anyway, to have somewhere to
    anchor the name. Such an address is a placeholder rather than a location, so
    it is deliberately not carried here -- and with no address, an instance
    cannot claim to be a stub either.
    """
