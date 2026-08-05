from __future__ import annotations

from abc import abstractmethod
from typing import Protocol, runtime_checkable


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
    def get_instr_bytes_at(self, addr: int, num_instr: int = 1) -> bytes:
        """Return the raw bytes of ``num_instr`` instructions starting at ``addr``."""
        ...

    @abstractmethod
    def get_unused_funcs(self) -> list[dict[str, int]]:
        """Return functions with no references to them, as ``addr``/``size`` dicts."""
        ...

    @abstractmethod
    def get_all_symbols(self) -> dict[str, int]:
        """Return a mapping of function symbol name to normalized address."""
        ...

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
