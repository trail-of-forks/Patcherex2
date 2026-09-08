import pytest
from archinfo import ArchARM, Endness

from patcherex2.components.binary_analyzer import (
    UnknownInstructionModeError,
)
from patcherex2.components.binary_analyzer.angr import AngrAnalyzer


class FakeSymbol:
    def __init__(self, name: str, address: int) -> None:
        self.name = name
        self.rebased_addr = address


class FakeNode:
    def __init__(self, address: int, thumb: bool) -> None:
        self.instruction_addrs = {address}
        self.thumb = thumb


class FakeAngrMainObject:
    def __init__(self, symbols: list[FakeSymbol]) -> None:
        self.mapped_base = 0
        self.pic = False
        self.symbols = symbols
        self.plt: dict[str, int] = {}

    def addr_to_offset(self, address: int) -> int:
        return address


class FakeAngrLoader:
    def __init__(self, main_object: FakeAngrMainObject) -> None:
        self.main_object = main_object


class FakeAngrProject:
    def __init__(self, main_object: FakeAngrMainObject) -> None:
        self.arch = ArchARM(Endness.LE)
        self.loader = FakeAngrLoader(main_object)
        self.analyses = object()
        self.kb = object()
        self.factory = object()


class FakeCfgModel:
    def __init__(self, nodes: list[FakeNode]) -> None:
        self._nodes = nodes

    def nodes(self) -> list[FakeNode]:
        return self._nodes

    def get_any_node(self, address: int, *, anyaddr: bool) -> FakeNode | None:
        del anyaddr
        return next(
            (node for node in self._nodes if address in node.instruction_addrs),
            None,
        )


class FakeCfg:
    def __init__(self, nodes: list[FakeNode]) -> None:
        self.model = FakeCfgModel(nodes)


def make_analyzer(
    mapping_symbols: list[tuple[str, int]], cfg_nodes: list[tuple[int, bool]]
) -> AngrAnalyzer:
    main_object = FakeAngrMainObject(
        [FakeSymbol(name, address) for name, address in mapping_symbols]
    )
    project = FakeAngrProject(main_object)
    cfg = FakeCfg([FakeNode(address, thumb) for address, thumb in cfg_nodes])
    return AngrAnalyzer(project, cfg)


def test_load_binary_uses_injected_angr_api():
    project = FakeAngrProject(FakeAngrMainObject([]))
    cfg = FakeCfg([])
    calls = []

    class FakeAngrApi:
        def create_project(self, binary_path, options):
            calls.append(("project", binary_path, options))
            return project

        def create_cfg(self, selected_project, options):
            assert selected_project is project
            calls.append(("cfg", options))
            return cfg

    with AngrAnalyzer.load_binary("firmware.elf", api=FakeAngrApi()) as analyzer:
        assert analyzer.project is project
        assert analyzer.cfg is cfg

    assert calls == [
        ("project", "firmware.elf", {"load_options": {"auto_load_libs": False}}),
        ("cfg", {"normalize": True}),
    ]


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
def test_thumb_mode_combines_mapping_symbols_and_cfg(mapping_symbols, cfg_nodes, expected):
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
