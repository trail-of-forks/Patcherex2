import os
from types import SimpleNamespace

import pytest

from patcherex2.components.binary_analyzers.angr import Angr
from patcherex2.components.binary_analyzers.ida import Ida
from patcherex2.components.compilers.compiler import UndefinedSymbolError
from patcherex2.targets import ElfAmd64Linux

BIN_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "test_binaries"
)
BINARY = os.path.join(BIN_LOCATION, "amd64", "printf_nopie")
EXTERN_DATA_CODE = (
    "extern char g_auth_token[128]; char *f(void) { return g_auth_token; }"
)


def make_compiler(symbols=None, binary_analyzer=None):
    patcherex = SimpleNamespace(
        symbols={} if symbols is None else symbols,
        binary_analyzer=(
            SimpleNamespace(get_all_symbols=dict)
            if binary_analyzer is None
            else binary_analyzer
        ),
    )
    patcherex.target = ElfAmd64Linux(patcherex, BINARY)
    patcherex.archinfo = patcherex.target.get_archinfo(None)
    return patcherex.target.get_compiler(None)


def test_angr_exports_object_symbols():
    analyzer = Angr(BINARY)

    assert "_IO_stdin_used" in analyzer.get_all_symbols()


def test_angr_excludes_imported_and_common_objects():
    imported = SimpleNamespace(
        name="imported",
        is_import=True,
        is_common=False,
        is_function=False,
        type=SimpleNamespace(name="TYPE_OBJECT"),
        rebased_addr=0,
    )
    common = SimpleNamespace(
        name="common",
        is_import=False,
        is_common=True,
        is_function=False,
        type=SimpleNamespace(name="TYPE_OBJECT"),
        rebased_addr=0,
    )
    defined = SimpleNamespace(
        name="defined",
        is_import=False,
        is_common=False,
        is_function=False,
        type=SimpleNamespace(name="TYPE_OBJECT"),
        rebased_addr=0x401000,
    )

    class FakeAngr(Angr):
        @property
        def cfg(self):
            return object()

        @property
        def p(self):
            return self._fake_p

    analyzer = FakeAngr.__new__(FakeAngr)
    analyzer._fake_p = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(symbols=[imported, common, defined])
        ),
        kb=SimpleNamespace(functions={}),
    )
    analyzer.normalize_addr = lambda addr: addr

    assert analyzer.get_all_symbols() == {"defined": 0x401000}


def test_ida_excludes_imported_data_but_keeps_functions_and_named_data():
    entries = [
        ("imported", 0x1000),
        ("imported", 0x2000),
        ("defined", 0x3000),
        ("code_label", 0x4000),
    ]
    analyzer = Ida.__new__(Ida)
    analyzer.ida_name = SimpleNamespace(
        get_nlist_size=lambda: len(entries),
        get_nlist_name=lambda index: entries[index][0],
        get_nlist_ea=lambda index: entries[index][1],
    )
    analyzer.ida_nalt = SimpleNamespace(
        get_import_module_qty=lambda: 1,
        enum_import_names=lambda _module, callback: callback(0x1000, "imported", 1),
    )
    analyzer.ida_idaapi = SimpleNamespace(BADADDR=-1)
    analyzer.ida_funcs = SimpleNamespace(
        get_func=lambda addr: object() if addr == 0x2000 else None
    )
    analyzer.ida_segment = SimpleNamespace(
        getseg=lambda _addr: SimpleNamespace(type=0, perm=4),
        SEG_XTRN=1,
        SEGPERM_EXEC=1,
        SEGPERM_READ=4,
        SEGPERM_WRITE=2,
    )
    analyzer.ida_bytes = SimpleNamespace(
        get_full_flags=lambda addr: addr,
        has_user_name=lambda flags: flags in (0x1000, 0x3000),
    )
    analyzer.normalize_addr = lambda addr: addr

    assert analyzer.get_all_symbols() == {
        "imported": 0x2000,
        "defined": 0x3000,
    }


def test_compile_accepts_analyzer_object_symbol():
    analyzer = Angr(BINARY)
    compiler = make_compiler(binary_analyzer=analyzer)

    assert compiler.compile(
        "extern int _IO_stdin_used; int f(void) { return _IO_stdin_used; }"
    )


def test_compile_rejects_unresolved_extern_data():
    with pytest.raises(UndefinedSymbolError, match="g_auth_token"):
        make_compiler().compile(EXTERN_DATA_CODE)


def test_compile_accepts_defined_extern_data():
    compiled = make_compiler({"g_auth_token": 0x404100}).compile(EXTERN_DATA_CODE)

    assert compiled
