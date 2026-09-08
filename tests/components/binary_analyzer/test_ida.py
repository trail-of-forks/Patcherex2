import sys
from types import ModuleType

import pytest

from patcherex2.components.binary_analyzer import BasicBlock, FunctionInfo
from patcherex2.components.binary_analyzer.ida import IDAAnalyzer
from patcherex2.components.binary_analyzer.symbol import MappedSymbol
from tests.support.fakes import FakeIdaApi, FakeIdaBlock, FakeIdaFunction, make_ida_analyzer


class FakeIdapro(ModuleType):
    """IDAlib lifecycle test double."""

    def __init__(self, *, open_status: int = 0) -> None:
        super().__init__("idapro")
        self.open_status = open_status
        self.open_calls: list[tuple[str, bool, str | None]] = []
        self.close_calls = 0

    def open_database(
        self, binary_path: str, run_auto_analysis: bool, arguments: str | None
    ) -> int:
        self.open_calls.append((binary_path, run_auto_analysis, arguments))
        return self.open_status

    def close_database(self) -> None:
        self.close_calls += 1


def install_fake_idalib(monkeypatch: pytest.MonkeyPatch, idapro: FakeIdapro) -> FakeIdaApi:
    """Install complete fake IDAlib modules for one test."""
    api = FakeIdaApi()
    monkeypatch.setitem(sys.modules, "idapro", idapro)
    for module_name in (
        "ida_bytes",
        "ida_funcs",
        "ida_gdl",
        "ida_ida",
        "ida_idaapi",
        "ida_idp",
        "ida_loader",
        "ida_nalt",
        "ida_name",
        "ida_segment",
        "ida_segregs",
        "idautils",
    ):
        monkeypatch.setitem(sys.modules, module_name, api)
    return api


def test_load_binary_owns_idalib_database_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    idapro = FakeIdapro()
    api = install_fake_idalib(monkeypatch, idapro)

    with IDAAnalyzer.load_binary("firmware.hex", processor="riscv") as analyzer:
        assert analyzer.ida_name is api
        assert idapro.close_calls == 0

    assert idapro.open_calls == [("firmware.hex", True, "-priscv")]
    assert idapro.close_calls == 1


def test_load_binary_reports_idalib_open_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    idapro = FakeIdapro(open_status=4)
    install_fake_idalib(monkeypatch, idapro)

    with (
        pytest.raises(RuntimeError, match=r"firmware\.elf.*status 4"),
        IDAAnalyzer.load_binary("firmware.elf"),
    ):
        pass

    assert idapro.close_calls == 0


def test_load_binary_closes_database_when_analysis_consumer_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idapro = FakeIdapro()
    install_fake_idalib(monkeypatch, idapro)

    with (
        pytest.raises(ValueError, match="consumer failed"),
        IDAAnalyzer.load_binary("firmware.elf"),
    ):
        raise ValueError("consumer failed")

    assert idapro.close_calls == 1


def test_unused_function_scan_iterates_function_indexes():
    functions = [
        FakeIdaFunction(start=0x1000, end=0x1020),
        FakeIdaFunction(start=0x2000, end=0x2030),
        None,
    ]

    ida = make_ida_analyzer(
        FakeIdaApi(
            indexed_functions=functions,
            xrefs_to=lambda address: [] if address == 0x1000 else [object()],
        )
    )

    assert ida.get_unused_funcs() == [FunctionInfo(addr=0x1000, size=0x20)]


def make_dll_analyzer() -> tuple[IDAAnalyzer, list[tuple[object, ...]]]:
    queried: list[tuple[object, ...]] = []
    function = FakeIdaFunction(
        start=0x401000,
        end=0x401008,
        instruction_addresses=(0x401000, 0x401004),
    )
    api = FakeIdaApi(
        function_for=lambda address: (
            queried.append(("func", address)) or function if address == 0x401000 else None
        ),
        blocks_for=lambda _function: [FakeIdaBlock(0x401000, 0x401008)],
        image_base=0x400000,
        is_dll=True,
        file_offset=lambda address: queried.append(("file", address)) or 0x100,
        item_size=lambda address: queried.append(("size", address)) or 4,
        item_bytes=lambda address, size: queried.append(("bytes", address, size)) or b"\x00" * size,
        register_number=15,
        segment_register=lambda address, register: queried.append(("sreg", address, register)) or 0,
    )
    return make_ida_analyzer(api), queried


def test_dll_address_is_denormalized_for_file_mapping():
    analyzer, queried = make_dll_analyzer()

    assert analyzer.mem_addr_to_file_offset(0x1000) == 0x100
    assert queried == [("file", 0x401000)]


def test_dll_address_is_denormalized_for_basic_block_lookup():
    analyzer, queried = make_dll_analyzer()

    assert analyzer.get_basic_block(0x1000) == BasicBlock(
        start=0x1000,
        size=8,
        instruction_addrs=(0x1000, 0x1004),
    )
    assert queried == [("func", 0x401000)]


def test_dll_address_is_denormalized_for_instruction_reads():
    analyzer, queried = make_dll_analyzer()

    assert analyzer.get_instr_bytes_at(0x1000) == b"\x00" * 4
    assert queried == [
        ("size", 0x401000),
        ("bytes", 0x401000, 4),
    ]


def test_dll_address_is_denormalized_for_instruction_mode():
    analyzer, queried = make_dll_analyzer()

    assert not analyzer.is_thumb(0x1000)
    assert queried == [("sreg", 0x401000, 15)]


def test_mem_addr_to_file_offset_rejects_unmapped_address():
    analyzer = make_ida_analyzer(FakeIdaApi(file_offset=lambda _address: -1))

    with pytest.raises(ValueError, match="0x1000"):
        analyzer.mem_addr_to_file_offset(0x1000)


def test_dll_thumb_symbol_mode_uses_the_original_ida_address():
    queried = []
    api = FakeIdaApi(
        entries=(("helper", 0x401000),),
        functions={0x401000: FakeIdaFunction(start=0x401000, end=0x401010)},
        image_base=0x400000,
        is_dll=True,
        segment_register=lambda address, _register: queried.append(address) or 1,
    )
    assert make_ida_analyzer(api).get_all_symbols() == {
        "helper": MappedSymbol(name="helper", addr=0x1001)
    }
    assert queried == [0x401000]


def test_data_inside_a_thumb_function_does_not_receive_the_thumb_bit():
    api = FakeIdaApi(
        entries=(("literal", 0x1008),),
        function_for=lambda _address: FakeIdaFunction(start=0x1000, end=0x1020),
        segment_register=lambda _address, _register: 1,
    )
    assert make_ida_analyzer(api).get_all_symbols() == {
        "literal": MappedSymbol(name="literal", addr=0x1008)
    }
