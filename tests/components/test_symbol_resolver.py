from patcherex2.components.binary_analyzer.symbol import MappedSymbol
from patcherex2.components.symbol_resolver import SymbolResolver
from tests.support.fakes import FakeBinaryAnalyzer


def test_patch_symbols_override_binary_symbols_and_explicit_symbols_override_both():
    resolver = SymbolResolver(
        FakeBinaryAnalyzer(symbols={"helper": MappedSymbol(name="helper", addr=0x1000)})
    )
    assert resolver.resolve() == {"helper": 0x1000}
    resolver.patch_symbols["helper"] = 0x2000
    assert resolver.resolve() == {"helper": 0x2000}
    assert resolver.resolve({"helper": 0x3000}) == {"helper": 0x3000}
    assert resolver.resolve() == {"helper": 0x2000}
