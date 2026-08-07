from types import SimpleNamespace

import pytest

from patcherex2.components.binary_analyzers.ida import IDAAnalyzer


def test_unused_function_scan_iterates_function_indexes():
    functions = [
        SimpleNamespace(start_ea=0x1000, end_ea=0x1020),
        SimpleNamespace(start_ea=0x2000, end_ea=0x2030),
        None,
    ]

    ida = IDAAnalyzer.__new__(IDAAnalyzer)
    ida.ida_funcs = SimpleNamespace(
        get_func_qty=lambda: len(functions),
        getn_func=lambda index: functions[index],
    )
    ida.idautils = SimpleNamespace(
        XrefsTo=lambda addr, _flags: [] if addr == 0x1000 else [object()]
    )
    ida.normalize_addr = lambda addr: addr

    assert ida.get_unused_funcs() == [{"addr": 0x1000, "size": 0x20}]


def test_dll_addresses_are_denormalized_at_all_ida_boundaries():
    queried = []
    function = SimpleNamespace(code_items=lambda: [0x401000, 0x401004])
    analyzer = IDAAnalyzer.__new__(IDAAnalyzer)
    analyzer._load_base = 0x400000
    analyzer.ida_ida = SimpleNamespace(inf_is_dll=lambda: True)
    analyzer.ida_loader = SimpleNamespace(
        get_file_type_name=lambda: "ELF",
        get_fileregion_offset=lambda addr: queried.append(("file", addr)) or 0x100,
    )
    analyzer.ida_funcs = SimpleNamespace(
        get_func=lambda addr: queried.append(("func", addr)) or function
    )
    analyzer.ida_gdl = SimpleNamespace(
        FC_PREDS=1,
        FlowChart=lambda **_kwargs: [
            SimpleNamespace(start_ea=0x401000, end_ea=0x401008)
        ],
    )
    analyzer.ida_bytes = SimpleNamespace(
        get_item_size=lambda addr: queried.append(("size", addr)) or 4,
        get_bytes=lambda addr, size: (
            queried.append(("bytes", addr, size)) or b"\x00" * size
        ),
    )
    analyzer.ida_idp = SimpleNamespace(str2reg=lambda _name: 15)
    analyzer.ida_segregs = SimpleNamespace(
        get_sreg=lambda addr, reg: queried.append(("sreg", addr, reg)) or 0
    )

    assert analyzer.mem_addr_to_file_offset(0x1000) == 0x100
    assert analyzer.get_basic_block(0x1000) == {
        "start": 0x1000,
        "end": 0x1008,
        "size": 8,
        "instruction_addrs": [0x1000, 0x1004],
    }
    assert analyzer.get_instr_bytes_at(0x1000) == b"\x00" * 4
    assert not analyzer.is_thumb(0x1000)
    assert queried == [
        ("file", 0x401000),
        ("func", 0x401000),
        ("size", 0x401000),
        ("bytes", 0x401000, 4),
        ("sreg", 0x401000, 15),
    ]


def test_mem_addr_to_file_offset_rejects_unmapped_address():
    analyzer = IDAAnalyzer.__new__(IDAAnalyzer)
    analyzer.ida_ida = SimpleNamespace(inf_is_dll=lambda: False)
    analyzer.ida_loader = SimpleNamespace(
        get_file_type_name=lambda: "ELF",
        get_fileregion_offset=lambda _addr: -1,
    )

    with pytest.raises(ValueError, match="0x1000"):
        analyzer.mem_addr_to_file_offset(0x1000)
