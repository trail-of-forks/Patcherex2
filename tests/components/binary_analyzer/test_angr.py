import pytest
from archinfo import ArchARM, Endness

from patcherex2.components.binary_analyzer import (
    UnknownInstructionModeError,
)
from patcherex2.components.binary_analyzer.angr import AngrAnalyzer
from tests.support.paths import TEST_BINARIES


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


@pytest.mark.parametrize("use_resolver", [False, True])
@pytest.mark.parametrize("options", [{}, {"normalize": False}])
def test_cfg_options_are_resolved_before_analysis_without_mutating_input(use_resolver, options):
    project = FakeAngrProject(FakeAngrMainObject([]))
    project.loader.main_object.mapped_base = 0x400000
    calls = []
    supplied = dict(options)

    def resolve(selected_project):
        assert selected_project is project
        assert calls == ["project"]
        calls.append("resolve")
        start = selected_project.loader.main_object.mapped_base + 0x100
        supplied.update(regions=[(start, start + 0x20)], function_starts=[start])
        return supplied

    class FakeAngrApi:
        def create_project(self, binary_path, options):
            calls.append("project")
            return project

        def create_cfg(self, selected_project, cfg_options):
            assert selected_project is project
            assert calls == (["project", "resolve"] if use_resolver else ["project"])
            calls.append("cfg")
            assert cfg_options == {"normalize": True, **supplied}
            assert cfg_options is not supplied
            return FakeCfg([])

    with AngrAnalyzer.load_binary(
        "firmware.elf",
        angr_cfg_kwargs=resolve if use_resolver else supplied,
        api=FakeAngrApi(),
    ) as analyzer:
        assert analyzer.project is project
        assert calls[-1] == "cfg"

    expected = dict(options)
    if use_resolver:
        expected.update(regions=[(0x400100, 0x400120)], function_starts=[0x400100])
    assert supplied == expected


def test_cfg_resolver_failure_prevents_analysis():
    failure = ValueError("Cannot resolve function scope")
    calls = []

    def resolve(project):
        calls.append("resolve")
        raise failure

    class FakeAngrApi:
        def create_project(self, binary_path, options):
            calls.append("project")
            return FakeAngrProject(FakeAngrMainObject([]))

        def create_cfg(self, project, options):
            pytest.fail("CFG construction must not run after scope resolution fails")

    with (
        pytest.raises(ValueError, match="Cannot resolve function scope") as caught,
        AngrAnalyzer.load_binary("firmware.elf", angr_cfg_kwargs=resolve, api=FakeAngrApi()),
    ):
        pytest.fail("A failed resolver must not yield an analyzer")

    assert caught.value is failure
    assert calls == ["project", "resolve"]


def test_cfg_resolver_recovers_real_symbol_function():
    scope = []

    def resolve(project):
        symbol = next(
            symbol for symbol in project.loader.main_object.symbols if symbol.name == "main"
        )
        start = symbol.rebased_addr
        assert symbol.size > 0
        scope.append((start, start + symbol.size))
        return {"regions": list(scope), "function_starts": [start]}

    binary = str(TEST_BINARIES / "amd64" / "printf_nopie")
    with AngrAnalyzer.load_binary(binary, angr_cfg_kwargs=resolve) as analyzer:
        assert len(scope) == 1
        start, _ = scope[0]
        assert analyzer.cfg.model.get_any_node(start, anyaddr=False) is not None
        entry = next(
            symbol
            for symbol in analyzer.project.loader.main_object.symbols
            if symbol.name == "_start"
        )
        assert analyzer.cfg.model.get_any_node(entry.rebased_addr, anyaddr=False) is None


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
