import os
import subprocess
from collections.abc import Sequence

import pytest

from patcherex2.components.binary_analyzer.angr import AngrAnalyzer
from patcherex2.components.binary_analyzer.symbol import MappedSymbol
from patcherex2.components.command_runner import (
    DEFAULT_COMMAND_RUNNER,
    CommandRunner,
)
from patcherex2.components.compilers.clang import ClangObjectCompiler
from patcherex2.components.compilers.elf import UndefinedSymbolError, create_elf_compiler
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.targets import ELF_AMD64_LINUX
from tests.support.fakes import (
    FakeBinaryAnalyzer,
    FakeIdaApi,
    FakeIdaFunction,
    FakeIdaSegment,
    FakeImageBackend,
    make_ida_analyzer,
)
from tests.support.paths import TEST_BINARIES

BIN_LOCATION = str(TEST_BINARIES)
BINARY = os.path.join(BIN_LOCATION, "amd64", "printf_nopie")
EXTERN_DATA_CODE = "extern char g_auth_token[128]; char *f(void) { return g_auth_token; }"


class FakeAngrSymbol:
    def __init__(
        self,
        name: str,
        address: int,
        *,
        is_import: bool = False,
        is_common: bool = False,
    ) -> None:
        self.name = name
        self.rebased_addr = address
        self.is_import = is_import
        self.is_common = is_common


class FakeAngrMainObject:
    def __init__(self, symbols: list[FakeAngrSymbol]) -> None:
        self.symbols = symbols
        self.plt: dict[str, int] = {}
        self.mapped_base = 0
        self.pic = False

    def addr_to_offset(self, address: int) -> int:
        return address


class FakeAngrLoader:
    def __init__(self, main_object: FakeAngrMainObject) -> None:
        self.main_object = main_object


class FakeAngrKnowledgeBase:
    def __init__(self) -> None:
        self.functions: dict[int, object] = {}


class FakeAngrProject:
    def __init__(self, main_object: FakeAngrMainObject) -> None:
        self.loader = FakeAngrLoader(main_object)
        self.kb = FakeAngrKnowledgeBase()
        self.arch = object()
        self.analyses = object()
        self.factory = object()


class FakeAngrCfgModel:
    def get_any_node(self, address: int, *, anyaddr: bool):
        del address, anyaddr

    def nodes(self):
        return ()


class FakeAngrCfg:
    def __init__(self) -> None:
        self.model = FakeAngrCfgModel()


def make_compiler(
    symbols=None,
    binary_analyzer=None,
    command_runner: CommandRunner = DEFAULT_COMMAND_RUNNER,
):
    binary_analyzer = FakeBinaryAnalyzer() if binary_analyzer is None else binary_analyzer
    image = FakeImageBackend()
    architecture = ELF_AMD64_LINUX.architecture
    symbol_resolver = SymbolResolver(binary_analyzer)
    symbol_resolver.patch_symbols.update({} if symbols is None else symbols)
    object_compiler = ClangObjectCompiler(
        15,
        ["-target", "x86_64-linux-gnu"],
        image.is_position_independent,
        architecture.info.non_pic_compiler_flags,
        command_runner=command_runner,
    )
    return create_elf_compiler(
        architecture=architecture.info,
        symbol_resolver=symbol_resolver,
        object_compiler=object_compiler,
        linker=object_compiler.linker,
        position_independent=image.is_position_independent,
        command_runner=command_runner,
    )


def test_angr_exports_object_symbols():
    with AngrAnalyzer.load_binary(BINARY) as analyzer:
        assert "_IO_stdin_used" in analyzer.get_all_symbols()


def test_angr_excludes_imported_and_common_objects():
    project = FakeAngrProject(
        FakeAngrMainObject(
            [
                FakeAngrSymbol("imported", 0, is_import=True),
                FakeAngrSymbol("common", 0, is_common=True),
                FakeAngrSymbol("defined", 0x401000),
            ]
        )
    )
    analyzer = AngrAnalyzer(project, FakeAngrCfg())

    assert analyzer.get_all_symbols() == {"defined": MappedSymbol(name="defined", addr=0x401000)}


def test_ida_excludes_imported_data_but_keeps_functions_and_named_data():
    entries = [
        ("imported", 0x1000),
        ("imported", 0x2000),
        ("defined", 0x3000),
        ("code_label", 0x4000),
    ]
    analyzer = make_ida_analyzer(
        FakeIdaApi(
            entries=entries,
            functions={0x4000: FakeIdaFunction(start=0x4000, end=0x4010)},
            segment_for=lambda address: FakeIdaSegment(
                1 if address in (0x1000, 0x2000) else 0,
                permissions=4,
            ),
        )
    )

    # The import is reported as external (no address), so it does not appear;
    # the defined datum and the code label both do.
    assert analyzer.get_all_symbols() == {
        "defined": MappedSymbol(name="defined", addr=0x3000),
        "code_label": MappedSymbol(name="code_label", addr=0x4000),
    }


def test_compile_accepts_analyzer_object_symbol():
    with AngrAnalyzer.load_binary(BINARY) as analyzer:
        compiler = make_compiler(binary_analyzer=analyzer)
        assert compiler.compile("extern int _IO_stdin_used; int f(void) { return _IO_stdin_used; }")


def test_compile_rejects_unresolved_extern_data():
    with pytest.raises(UndefinedSymbolError, match="g_auth_token"):
        make_compiler().compile(EXTERN_DATA_CODE)


def test_compile_accepts_defined_extern_data():
    compiled = make_compiler({"g_auth_token": 0x404100}).compile(EXTERN_DATA_CODE)

    assert compiled


def test_compile_recompiles_object_and_relinks_for_each_base():
    symbol_calls = 0

    def get_all_symbols():
        nonlocal symbol_calls
        symbol_calls += 1
        return {}

    class CountingAnalyzer(FakeBinaryAnalyzer):
        def get_all_symbols(self):
            return get_all_symbols()

    compile_calls = 0
    link_calls = 0

    class RecordingCommandRunner:
        def run(self, args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
            nonlocal compile_calls, link_calls
            if "-c" in args:
                compile_calls += 1
            elif args[0] == "ld.lld-15":
                link_calls += 1
            return DEFAULT_COMMAND_RUNNER.run(args)

    runner: CommandRunner = RecordingCommandRunner()
    compiler = make_compiler(
        {"external": 0x400000},
        binary_analyzer=CountingAnalyzer(),
        command_runner=runner,
    )

    code = "extern int external(void); int f(void) { return external(); }"

    first = compiler.compile(code, base=0x1000)
    second = compiler.compile(code, base=0x2000)

    assert first != second
    assert compile_calls == 2
    assert link_calls == 2
    assert symbol_calls == 1
