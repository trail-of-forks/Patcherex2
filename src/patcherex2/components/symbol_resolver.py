from __future__ import annotations

from collections.abc import Mapping

from patcherex2.components.binary_analyzer import BinaryAnalyzer


class SymbolResolver:
    """Combines symbols discovered in the image with symbols added by patches."""

    def __init__(self, binary_analyzer: BinaryAnalyzer) -> None:
        self.binary_analyzer = binary_analyzer
        self.patch_symbols: dict[str, int] = {}
        self._binary_symbols: dict[str, int] | None = None

    def resolve(self, explicit: Mapping[str, int] | None = None) -> dict[str, int]:
        """Return symbols in increasing precedence order."""
        if self._binary_symbols is None:
            self._binary_symbols = {
                name: symbol.addr for name, symbol in self.binary_analyzer.get_all_symbols().items()
            }
        symbols = dict(self._binary_symbols)
        symbols.update(self.patch_symbols)
        if explicit is not None:
            symbols.update(explicit)
        return symbols
