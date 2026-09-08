import os
import subprocess

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2.components.arch import ArchitectureInfo
from patcherex2.components.arch.x86 import X86
from patcherex2.components.binary_analyzer.symbol import MappedSymbol
from patcherex2.components.compilers import (
    CompilationEngine,
    Compiler,
    CompilerPipeline,
    ObjectCompiler,
)
from patcherex2.components.compilers.elf import (
    ElfCompilationEngine,
    ObjectArchMismatchError,
    UnsupportedRelocationError,
)
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.targets import (
    ELF_AARCH64_LINUX,
    ELF_AMD64_LINUX,
    ELF_AMD64_LINUX_RECOMP,
    ELF_ARM_LINUX,
    ELF_MIPS64_LINUX,
    ELF_MIPS64EL_LINUX,
    ELF_MIPS_LINUX,
    ELF_MIPSEL_LINUX,
    ELF_PPC64_LINUX,
    ELF_PPC64LE_LINUX,
    ELF_PPC_LINUX,
    ELF_S390X_LINUX,
    ELF_X86_LINUX,
)
from tests.support.fakes import FakeBinaryAnalyzer
from tests.support.paths import TEST_BINARIES

BIN_LOCATION = str(TEST_BINARIES)
EXTERN_DATA_CODE = "extern char g_auth_token[128]; char *f(void) { return g_auth_token; }"
DEFAULT_VISIBILITY_EXTERN_DATA_CODE = """
extern char g_auth_token[128] __attribute__((visibility("default")));
char *f(void) { return g_auth_token; }
"""
C_CODE = "int f(int x) { return x + 1; }"
TARGETS = [
    (ELF_AMD64_LINUX, "amd64/printf_nopie"),
    (ELF_X86_LINUX, "x86/printf_nopie"),
    (ELF_AARCH64_LINUX, "aarch64/printf_nopie"),
    (ELF_ARM_LINUX, "armhf/printf_nopie"),
    (ELF_MIPS_LINUX, "mips/printf_nopie"),
    (ELF_MIPSEL_LINUX, "mipsel/printf_nopie"),
    (ELF_MIPS64_LINUX, "mips64/printf_nopie"),
    (ELF_MIPS64EL_LINUX, "mips64el/printf_nopie"),
    (ELF_PPC_LINUX, "ppc/printf_nopie"),
    (ELF_PPC64_LINUX, "ppc64/printf_nopie"),
    (ELF_PPC64LE_LINUX, "ppc64le/printf_nopie"),
    (ELF_S390X_LINUX, "s390x/printf_nopie"),
]
PPC64_TARGETS = [
    (ELF_PPC64_LINUX, "ppc64/printf_nopie"),
    (ELF_PPC64LE_LINUX, "ppc64le/printf_nopie"),
]
# PPC64 external data uses the ABI's TOC and is covered by the explicit
# rejection cases rather than the direct-address success matrix.
DIRECT_EXTERNAL_DATA_TARGETS = [
    (target, binary)
    for target, binary in TARGETS
    if target is not ELF_PPC64_LINUX and target is not ELF_PPC64LE_LINUX
]
RECOMP_TARGETS = [
    (ELF_AMD64_LINUX_RECOMP, "amd64/printf_nopie"),
    (ELF_AMD64_LINUX_RECOMP, "amd64/printf_pie"),
]


def binary_arch(path):
    with open(path, "rb") as binary:
        elf = ELFFile(binary)
        return {
            "e_machine": elf.header["e_machine"],
            "ei_class": elf.header["e_ident"]["EI_CLASS"],
            "ei_data": elf.header["e_ident"]["EI_DATA"],
        }


def target_arch(target_definition, binary):
    del binary
    return target_definition.architecture.info.elf_arch


def make_elf_engine(
    architecture: ArchitectureInfo = X86,
    *,
    is_position_independent: bool = False,
) -> ElfCompilationEngine:
    analyzer = FakeBinaryAnalyzer()
    return ElfCompilationEngine(
        architecture=architecture,
        symbol_resolver=SymbolResolver(analyzer),
        linker="ld",
        position_independent=is_position_independent,
    )


class StubObjectCompiler:
    preserve_none = False

    def compile_object(self, code, extension=".c", extra_compiler_flags=None, **kwargs):
        del code, extension, extra_compiler_flags, kwargs
        return b"object"


class StubCompilationEngine:
    def compile(self, object_bytes, base=0, symbols=None):
        del object_bytes, base, symbols
        return b"compiled"


def test_compiler_is_structural():
    object_compiler: ObjectCompiler = StubObjectCompiler()
    compilation_engine: CompilationEngine = StubCompilationEngine()
    pipeline = CompilerPipeline(
        object_compiler,
        compilation_engine,
    )
    assert isinstance(pipeline, Compiler)


def compiler_position_flags(compiler):
    pipeline = getattr(compiler, "compiler", compiler)
    return list(pipeline.object_compiler.position_flags())


def check_object_arch(expected, path):
    compiler = make_elf_engine(X86.model_copy(update={"elf_arch": expected}))
    with open(path, "rb") as binary:
        compiler.check_object_arch(ELFFile(binary))


class TestObjectArchCheck:
    @pytest.mark.parametrize("target_definition,binary", TARGETS)
    def test_archinfo_matches_target_binary(self, target_definition, binary):
        path = os.path.join(BIN_LOCATION, binary)
        assert target_arch(target_definition, binary) == binary_arch(path)

    def test_wrong_machine_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="e_machine"):
            check_object_arch(
                target_arch(ELF_AMD64_LINUX, "amd64/printf_nopie"),
                os.path.join(BIN_LOCATION, "aarch64/printf_nopie"),
            )

    def test_wrong_class_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="ei_class"):
            check_object_arch(
                target_arch(ELF_MIPS64_LINUX, "mips64/printf_nopie"),
                os.path.join(BIN_LOCATION, "mips/printf_nopie"),
            )

    def test_wrong_endianness_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="ei_data"):
            check_object_arch(
                target_arch(ELF_PPC64_LINUX, "ppc64/printf_nopie"),
                os.path.join(BIN_LOCATION, "ppc64le/printf_nopie"),
            )

    def test_every_compiler_target_has_archinfo(self):
        missing = []
        for target_definition, _binary in TARGETS:
            archinfo = target_definition.architecture.info
            if not getattr(archinfo, "elf_arch", None):
                missing.append(target_definition.name)
        assert not missing, f"targets without archinfo.elf_arch: {missing}"


class TestPicCompilerFlags:
    @pytest.mark.parametrize("target_definition,binary", TARGETS)
    def test_fixed_targets_disable_pic(self, target_definition, binary):
        patch_session = CompilerHarness(target_definition, os.path.join(BIN_LOCATION, binary))
        compiler = patch_session.compiler
        expected = ["-fno-pic"]
        if target_definition in (
            ELF_MIPS_LINUX,
            ELF_MIPSEL_LINUX,
            ELF_MIPS64_LINUX,
            ELF_MIPS64EL_LINUX,
        ):
            expected.append("-mno-abicalls")

        assert compiler_position_flags(compiler) == expected

    def test_pie_targets_keep_pic(self):
        patch_session = CompilerHarness(
            ELF_AMD64_LINUX, os.path.join(BIN_LOCATION, "amd64/printf_pie")
        )
        compiler = patch_session.compiler

        assert compiler_position_flags(compiler) == []

    @pytest.mark.parametrize("target_definition,binary", PPC64_TARGETS)
    def test_ppc64_toc_relocation_fails_loudly(self, target_definition, binary):
        patch_session = CompilerHarness(
            target_definition,
            os.path.join(BIN_LOCATION, binary),
        )
        patch_session.symbols["g_auth_token"] = 0x404100

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patch_session.compiler.compile(EXTERN_DATA_CODE)


class CompilerHarness:
    def __init__(self, target_definition, binary_path, binary_analyzer=None):
        self.binary_path = binary_path
        self.target = target_definition
        architecture = target_definition.architecture
        image = target_definition.image
        self.archinfo = architecture.info
        self.binary_analyzer = binary_analyzer or FakeBinaryAnalyzer()
        self.image = image.backend.select(None)(binary_path)
        self.allocation_manager = image.allocator.select(None)(
            self.binary_analyzer,
            self.image,
        )
        self.symbol_resolver = SymbolResolver(self.binary_analyzer)
        self.symbols = self.symbol_resolver.patch_symbols
        self.assembler = architecture.assembler.select(None)(self.symbol_resolver)
        self.disassembler = architecture.disassembler.select(None)()
        self.compiler = architecture.compiler.select(None)(
            architecture=self.archinfo,
            image=self.image,
            symbol_resolver=self.symbol_resolver,
            assembler=self.assembler,
            disassembler=self.disassembler,
        )


class TestCompiledObjectArch:
    @pytest.mark.parametrize("target_definition,binary", TARGETS)
    def test_compiles_for_target_arch(self, target_definition, binary):
        path = os.path.join(BIN_LOCATION, binary)
        patch_session = CompilerHarness(target_definition, path)
        # compile() validates the generated object's architecture before linking.
        assert patch_session.compiler.compile(C_CODE)


# Same function as C_CODE, as LLVM IR: add 1 to the argument and return it.
LLVM_IR_CODE = """define i32 @f(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
"""


class TestSourceExtension:
    """
    ``extension`` selects how clang reads the source, so a patch can be written
    in LLVM IR instead of C. Patches reach it through ``compile_opts``.
    """

    def test_compiles_llvm_ir(self):
        p = CompilerHarness(ELF_AMD64_LINUX, os.path.join(BIN_LOCATION, "amd64/printf_nopie"))
        compiler = p.compiler
        # mov eax, edi / add eax, 1 / ret
        assert compiler.compile(LLVM_IR_CODE, extension=".ll") == bytes.fromhex("89f883c001c3")

    def test_defaults_to_c(self):
        p = CompilerHarness(ELF_AMD64_LINUX, os.path.join(BIN_LOCATION, "amd64/printf_nopie"))
        compiler = p.compiler
        assert compiler.compile(C_CODE)

    def test_llvm_ir_rejected_as_c(self):
        # Guards against extension being ignored: IR fed to the C frontend must
        # not silently compile.
        p = CompilerHarness(ELF_AMD64_LINUX, os.path.join(BIN_LOCATION, "amd64/printf_nopie"))
        compiler = p.compiler
        with pytest.raises(subprocess.CalledProcessError):
            compiler.compile(LLVM_IR_CODE)


# References an extern global, which is what makes the compiler choose between
# materializing the address and loading it from the GOT.
EXTERN_DATA_C_CODE = "extern char g_auth_token[128];\nchar *f(void) { return g_auth_token; }\n"

# The address the linker script would define g_auth_token at, standing in for
# a symbol read out of the target binary.
EXTERN_DATA_SYMBOLS = {"g_auth_token": 0x404100}


class TestRecompiledObjectArch:
    @pytest.mark.parametrize("target_definition,binary", RECOMP_TARGETS)
    def test_recomp_compiles_for_target_arch(self, target_definition, binary):
        path = os.path.join(BIN_LOCATION, binary)
        patch_session = CompilerHarness(target_definition, path)
        assert patch_session.compiler.compile(C_CODE)


class TestGotRelocationCheck:
    """
    Patch code that reaches an extern global through the GOT, while the linker
    script defines that global as an absolute address, produces a binary that
    loads from the datum's address instead of using it. The final link is
    ``-relocatable``, so nothing diagnoses this; the check is what turns it
    into a build-time error rather than a runtime segfault.
    """

    def _compile_pic_object(self, tmp_path):
        src = tmp_path / "code.c"
        src.write_text(EXTERN_DATA_C_CODE)
        obj = tmp_path / "pic.o"
        # No -fno-pic: clang emits a GOT-indirect reference.
        subprocess.run(
            ["clang-15", "-target", "x86_64-linux-gnu", "-c", str(src), "-o", str(obj)],
            check=True,
            capture_output=True,
        )
        return obj

    def test_pic_object_raises(self, tmp_path):
        obj = self._compile_pic_object(tmp_path)
        compiler = make_elf_engine()
        with (
            open(obj, "rb") as f,
            pytest.raises(UnsupportedRelocationError, match="g_auth_token"),
        ):
            compiler.check_got_relocations(ELFFile(f), set(EXTERN_DATA_SYMBOLS))

    def test_symbols_we_do_not_define_are_ignored(self, tmp_path):
        # A GOT reference to a symbol the linker script does not define as an
        # absolute is none of this check's business.
        obj = self._compile_pic_object(tmp_path)
        compiler = make_elf_engine()
        with open(obj, "rb") as f:
            compiler.check_got_relocations(ELFFile(f), {"unrelated"})

    def test_pie_target_rejects_got_reference_to_defined_symbol(self, tmp_path):
        obj = self._compile_pic_object(tmp_path)

        compiler = make_elf_engine(is_position_independent=True)
        with (
            open(obj, "rb") as f,
            pytest.raises(UnsupportedRelocationError, match="g_auth_token"),
        ):
            compiler.check_got_relocations(ELFFile(f), set(EXTERN_DATA_SYMBOLS))

    @pytest.mark.parametrize("target_definition,binary", DIRECT_EXTERNAL_DATA_TARGETS)
    def test_target_flags_avoid_got_indirection(self, target_definition, binary):
        # The real regression: each supported target's compiler flags must
        # resolve an extern global to its address rather than through the GOT.
        # compile() runs check_got_relocations internally, so a target whose
        # flags let PIC codegen through raises here. Every binary in this matrix
        # is non-PIE.
        p = CompilerHarness(
            target_definition,
            os.path.join(BIN_LOCATION, binary),
            binary_analyzer=FakeBinaryAnalyzer(
                symbols={
                    name: MappedSymbol(name=name, addr=addr)
                    for name, addr in EXTERN_DATA_SYMBOLS.items()
                }
            ),
        )
        compiler = p.compiler
        assert compiler.compile(EXTERN_DATA_C_CODE)


class TestPieDetection:
    """
    -fno-pic is correct only for non-PIE binaries: on a PIE target it makes the
    patch's own rodata references absolute, which is wrong once the patch is
    relocated into a cave.
    """

    @pytest.mark.parametrize(
        "target_definition",
        [ELF_AMD64_LINUX, ELF_AMD64_LINUX_RECOMP],
    )
    def test_pie_compiles_direct_fixed_symbol_reference(self, target_definition):
        path = os.path.join(BIN_LOCATION, "amd64/printf_pie")
        patch_session = CompilerHarness(target_definition, path)
        patch_session.symbols["g_auth_token"] = 0x2007

        compiled = patch_session.compiler.compile(EXTERN_DATA_CODE)
        instructions = patch_session.disassembler.disassemble(compiled)

        assert any(
            instruction["mnemonic"] == "lea"
            and "[rip + " in instruction["op_str"]
            and instruction["address"]
            + instruction["size"]
            + int(instruction["op_str"].rsplit("+ ", 1)[1].rstrip("]"), 16)
            == 0x2007
            for instruction in instructions
        )

    @pytest.mark.parametrize(
        "target_definition",
        [ELF_AMD64_LINUX, ELF_AMD64_LINUX_RECOMP],
    )
    def test_pie_rejects_residual_got_reference(self, target_definition):
        path = os.path.join(BIN_LOCATION, "amd64/printf_pie")
        patch_session = CompilerHarness(target_definition, path)
        patch_session.symbols["g_auth_token"] = 0x2007

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patch_session.compiler.compile(DEFAULT_VISIBILITY_EXTERN_DATA_CODE)

    def test_fixed_recomp_embeds_absolute_external_data_address(self):
        path = os.path.join(BIN_LOCATION, "amd64/printf_nopie")
        patch_session = CompilerHarness(ELF_AMD64_LINUX_RECOMP, path)
        patch_session.symbols["g_auth_token"] = 0x404100

        compiled = patch_session.compiler.compile(EXTERN_DATA_CODE)
        instructions = patch_session.disassembler.disassemble(compiled)

        assert any("0x404100" in instruction["op_str"] for instruction in instructions)

    def test_fixed_recomp_rejects_forced_pic(self):
        path = os.path.join(BIN_LOCATION, "amd64/printf_nopie")
        patch_session = CompilerHarness(ELF_AMD64_LINUX_RECOMP, path)
        patch_session.symbols["g_auth_token"] = 0x404100

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patch_session.compiler.compile(EXTERN_DATA_CODE, extra_compiler_flags=["-fPIC"])

    @pytest.mark.parametrize(
        "target_definition,binary",
        [
            (ELF_AMD64_LINUX, "amd64/replace_function_patch"),
            (ELF_ARM_LINUX, "armhf/replace_function_patch"),
        ],
    )
    def test_pie_binaries_keep_pic(self, target_definition, binary):
        p = CompilerHarness(target_definition, os.path.join(BIN_LOCATION, binary))
        assert p.image.is_position_independent
        assert "-fno-pic" not in compiler_position_flags(p.compiler)


class TestLinkerScriptNames:
    """
    Analyzers name things the binary never named -- string contents, struct and
    array members. Those names are not identifiers, and the linker tries to read
    a bracketed run in one as a glob character class, which aborts the parse and
    fails the link for *any* patch, not just one referencing such a name.
    """

    #: A real Ghidra label for a format string, and the shape that broke the
    #: link: the bracket run is truncated by the ``%`` that follows it.
    POISON = "s_[%s]_patient=%d_drug=%s_dose=%dm_004022c7"

    def test_drops_names_the_linker_cannot_parse(self):
        kept = ElfCompilationEngine.linker_script_symbols(
            {"g_auth_token": 0x404100, self.POISON: 0x4022C7}
        )
        assert kept == {"g_auth_token": 0x404100}

    @pytest.mark.parametrize(
        "name",
        [
            "g_auth_token",  # ordinary global
            "check_auth",  # ordinary function
            "completed.0",  # a dot is legal in a linker script
            "$a",  # and so is a dollar
            "_Z5addupIiET_S0_S0_",  # C++ arrives mangled, so it is an identifier
        ],
    )
    def test_keeps_referenceable_names(self, name):
        assert ElfCompilationEngine.linker_script_symbols({name: 0x1000}) == {name: 0x1000}

    @pytest.mark.parametrize(
        "name",
        [
            "s_[%s]_patient=%d_004022c7",
            "s_/var/log/medispense.log_004022ad",
            "g_inventory[0].drug[63]",
            "ElfComment[0]",
            "main+1",
            "s_check(10,_%d)_->_%d_00402004",
        ],
    )
    def test_drops_generated_labels(self, name):
        assert ElfCompilationEngine.linker_script_symbols({name: 0x1000}) == {}

    def test_drops_the_location_counter(self):
        # `.` is the output position, not a name: assigning to it would move
        # the section end rather than define anything, silently inflating the
        # patch to wherever the address points.
        assert ElfCompilationEngine.linker_script_symbols({".": 0x2000, "a": 0x1}) == {"a": 0x1}

    def test_one_bad_name_does_not_take_the_others(self):
        # The failure this guards against was total: the whole script was
        # rejected, so every valid symbol was lost with the one bad one.
        symbols = {"a": 0x1, self.POISON: 0x2, "b": 0x3}
        assert ElfCompilationEngine.linker_script_symbols(symbols) == {
            "a": 0x1,
            "b": 0x3,
        }
