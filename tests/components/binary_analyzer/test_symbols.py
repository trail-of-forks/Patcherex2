from collections.abc import Iterable, Iterator

from patcherex2.components.binary_analyzer import BinaryAnalyzer
from patcherex2.components.binary_analyzer.symbol import MappedSymbol, Symbol
from tests.support.fakes import FakeBinaryAnalyzer


class AnalyzerWithDuplicateSymbols(FakeBinaryAnalyzer):
    """Exercise the shared analyzer policy with an ordered symbol stream."""

    def __init__(self, symbols: Iterable[Symbol]) -> None:
        super().__init__()
        self._duplicate_symbols = tuple(symbols)

    def iter_symbols(self) -> Iterator[Symbol]:
        yield from self._duplicate_symbols

    def get_all_symbols(self) -> dict[str, MappedSymbol]:
        return BinaryAnalyzer.get_all_symbols(self)


def test_same_name_and_address_are_deduplicated():
    analyzer = AnalyzerWithDuplicateSymbols(
        [
            MappedSymbol(name="main", addr=0x401000),
            MappedSymbol(name="main", addr=0x401000),
        ]
    )

    assert analyzer.get_all_symbols() == {"main": MappedSymbol(name="main", addr=0x401000)}


def test_same_name_at_different_addresses_remains_ambiguous():
    analyzer = AnalyzerWithDuplicateSymbols(
        [
            MappedSymbol(name="main", addr=0x401000),
            MappedSymbol(name="main", addr=0x402000),
        ]
    )

    assert analyzer.get_all_symbols() == {}
