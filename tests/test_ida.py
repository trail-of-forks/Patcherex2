from types import SimpleNamespace

from patcherex2.components.binary_analyzers.ida import Ida


def test_unused_function_scan_iterates_function_indexes():
    functions = [
        SimpleNamespace(start_ea=0x1000, size=0x20),
        SimpleNamespace(start_ea=0x2000, size=0x30),
        None,
    ]

    ida = Ida.__new__(Ida)
    ida.ida_funcs = SimpleNamespace(
        get_func_qty=lambda: len(functions),
        getn_func=lambda index: functions[index],
    )
    ida.idautils = SimpleNamespace(
        XrefsTo=lambda addr, _flags: [] if addr == 0x1000 else [object()]
    )
    ida.normalize_addr = lambda addr: addr

    assert ida.get_unused_funcs() == [{"addr": 0x1000, "size": 0x20}]
