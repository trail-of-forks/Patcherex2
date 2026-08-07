from types import SimpleNamespace

import pytest
from archinfo import ArchARM, Endness

from patcherex2.components.binary_analyzers.angr import AngrAnalyzer
from patcherex2.components.binary_analyzers.binary_analyzer import (
    UnknownInstructionModeError,
)


class FakeSymbol:
    def __init__(self, name: str, address: int) -> None:
        self.name = name
        self.rebased_addr = address


class FakeNode:
    def __init__(self, address: int, thumb: bool) -> None:
        self.instruction_addrs = {address}
        self.thumb = thumb


def make_analyzer(
    mapping_symbols: list[tuple[str, int]], cfg_nodes: list[tuple[int, bool]]
) -> AngrAnalyzer:
    main_object = SimpleNamespace(
        mapped_base=0,
        pic=False,
        symbols=[FakeSymbol(name, address) for name, address in mapping_symbols],
    )
    analyzer = AngrAnalyzer.__new__(AngrAnalyzer)
    analyzer._p = SimpleNamespace(
        arch=ArchARM(Endness.LE),
        loader=SimpleNamespace(main_object=main_object),
    )
    analyzer._cfg = SimpleNamespace(
        model=SimpleNamespace(
            nodes=lambda: [FakeNode(address, thumb) for address, thumb in cfg_nodes]
        )
    )
    analyzer._load_base = 0
    analyzer._mapping_symbols = None
    return analyzer


@pytest.mark.parametrize(
    ("mapping_symbols", "cfg_nodes", "expected"),
    [
        (["$t"], [(0x101, True)], True),
        (["$a"], [(0x101, False)], False),
        (["$t"], [], True),
        (["$a"], [], False),
        ([], [(0x101, True)], True),
        ([], [(0x101, False)], False),
        (["$t"], [(0x101, False)], None),
        (["$a"], [(0x101, True)], None),
        (["$d"], [(0x101, True)], None),
        (["$d"], [], None),
        ([], [], None),
    ],
)
def test_thumb_mode_combines_mapping_symbols_and_cfg(
    mapping_symbols, cfg_nodes, expected
):
    analyzer = make_analyzer([(name, 0x100) for name in mapping_symbols], cfg_nodes)

    assert analyzer.thumb_mode(0x100) is expected


def test_thumb_mode_uses_mapping_symbol_ranges():
    analyzer = make_analyzer([("$t", 0x100), ("$a", 0x200)], [])

    assert analyzer.thumb_mode(0x1FF) is True
    assert analyzer.thumb_mode(0x200) is False


def test_is_thumb_rejects_unknown_mode():
    analyzer = make_analyzer([("$t", 0x100)], [(0x101, False)])

    with pytest.raises(UnknownInstructionModeError, match="0x100"):
        analyzer.is_thumb(0x100)


def test_get_instr_bytes_at_rejects_unknown_mode():
    analyzer = make_analyzer([], [])

    with pytest.raises(UnknownInstructionModeError, match="0x100"):
        analyzer.get_instr_bytes_at(0x100)
