from __future__ import annotations

import logging
from abc import abstractmethod
from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from .symbol import MappedSymbol, Symbol

logger = logging.getLogger(__name__)


class UnknownInstructionModeError(RuntimeError):
    """Raised when an instruction's architecture mode cannot be determined."""


@runtime_checkable
class BinaryAnalyzer(Protocol):
    """Structural interface implemented by every binary analyzer backend.

    Addresses crossing this interface are *normalized*: relative to the image
    base for position-independent binaries, absolute otherwise. Backends
    translate to and from their own address space with
    :meth:`normalize_addr` / :meth:`denormalize_addr`.
    """

    @property
    @abstractmethod
    def load_base(self) -> int:
        """Base address the binary is mapped at by the underlying analyzer."""
        ...

    @abstractmethod
    def normalize_addr(self, addr: int) -> int:
        """Convert an analyzer address to a normalized address."""
        ...

    @abstractmethod
    def denormalize_addr(self, addr: int) -> int:
        """Convert a normalized address to an analyzer address."""
        ...

    @abstractmethod
    def mem_addr_to_file_offset(self, addr: int) -> int:
        """Map a normalized memory address to its offset in the binary file."""
        ...

    @abstractmethod
    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        """Return the basic block containing ``addr``.

        The returned mapping has keys ``start``, ``end``, ``size`` and
        ``instruction_addrs``, with all addresses normalized.
        """
        ...

    @abstractmethod
    def get_instr_bytes_at(self, addr: int, num_instr: int = 1) -> bytes | None:
        """Return the raw bytes of ``num_instr`` instructions starting at ``addr``.

        ``None`` is returned when no instruction is found at ``addr``.
        """
        ...

    @abstractmethod
    def get_unused_funcs(self) -> list[dict[str, int]]:
        """Return functions with no references to them, as ``addr``/``size`` dicts."""
        ...

    @abstractmethod
    def iter_symbols(self) -> Iterator[Symbol]:
        """Yield every symbol the analyzer knows about, code and data alike.

        This reports *facts*, not policy. A backend yields what it found and
        does not decide what is usable, nor which of two same-named symbols
        wins; that is settled once in :meth:`get_all_symbols` so backends
        cannot drift from one another.

        Specifically, a backend should:

        - yield data symbols as well as functions, so patch code can reference
          an existing global by ``extern``;
        - yield an :class:`ExternalSymbol` for anything whose definition lives
          outside this binary, rather than passing on an address its own
          analysis invented to anchor the name;
        - mark a :class:`MappedSymbol` as a stub when its address is a
          trampoline forwarding to the thing named;
        - apply any instruction-set encoding to code addresses, so they are
          usable branch targets, and never to data;
        - report names verbatim, including ones no consumer can reference --
          filtering those is the caller's job, via
          :attr:`Symbol.is_asm_usable` and :attr:`Symbol.is_c_usable`.
        """
        ...

    def get_all_symbols(self) -> dict[str, MappedSymbol]:
        """Return the symbols a patch can resolve a reference to, by name.

        Only :class:`MappedSymbol` appears: a name with no address cannot
        resolve a reference, and offering one would hand out a placeholder.
        The symbol itself is returned rather than just its address so a caller
        can tell a trampoline from a definition.

        A name may legitimately be reported more than once -- typically a
        trampoline alongside what it forwards to. Where the addresses agree the
        duplicate is redundant; where they differ, the non-stub wins, since
        that is where the thing named actually lives. A name with two non-stub
        addresses is genuinely ambiguous, so it is dropped rather than resolved
        arbitrarily, and a patch referring to it will fail to resolve instead
        of silently reaching the wrong one.
        """
        best: dict[str, MappedSymbol] = {}
        ambiguous: set[str] = set()
        for symbol in self.iter_symbols():
            if not isinstance(symbol, MappedSymbol):
                continue

            if existing := best.get(symbol.name):
                if not symbol.is_stub:
                    if existing.is_stub:
                        best[symbol.name] = symbol
                    else:
                        ambiguous.add(symbol.name)

            else:
                best[symbol.name] = symbol

        for name in ambiguous:
            logger.warning(
                "symbol %r has more than one address and no way to choose "
                "between them; patches cannot reference it by name",
                name,
            )
            del best[name]
        return best

    @abstractmethod
    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        """Return the function named or containing ``name_or_addr``, if any.

        The returned mapping has keys ``addr`` and ``size``; ``None`` is
        returned when no such function exists.
        """
        ...

    @abstractmethod
    def is_thumb(self, addr: int) -> bool:
        """Whether ``addr`` holds Thumb-mode code (always false off ARM)."""
        ...
