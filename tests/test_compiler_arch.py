#!/usr/bin/env python

# ruff: noqa
import os
import subprocess

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2.components.compilers.compiler import (
    Compiler,
    IndirectSymbolReferenceError,
    ObjectArchMismatchError,
)
from patcherex2.targets import (
    ElfAArch64Linux,
    ElfAmd64Linux,
    ElfArmLinux,
    ElfMips64elLinux,
    ElfMips64Linux,
    ElfMipselLinux,
    ElfMipsLinux,
    ElfPpc64leLinux,
    ElfPpc64Linux,
    ElfPpcLinux,
    ElfS390xLinux,
    ElfX86Linux,
    Target,
)

bin_location = str(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_binaries")
)

# Targets that compile patch code, and a binary of that architecture to drive
# them with. Each entry must produce an object matching its own target.
TARGETS = [
    (ElfAmd64Linux, "amd64/printf_nopie"),
    (ElfX86Linux, "x86/printf_nopie"),
    (ElfAArch64Linux, "aarch64/printf_nopie"),
    (ElfArmLinux, "armhf/printf_nopie"),
    (ElfMipsLinux, "mips/printf_nopie"),
    (ElfMipselLinux, "mipsel/printf_nopie"),
    (ElfMips64Linux, "mips64/printf_nopie"),
    (ElfMips64elLinux, "mips64el/printf_nopie"),
    (ElfPpcLinux, "ppc/printf_nopie"),
    (ElfPpc64Linux, "ppc64/printf_nopie"),
    (ElfPpc64leLinux, "ppc64le/printf_nopie"),
    (ElfS390xLinux, "s390x/printf_nopie"),
]

C_CODE = "int f(int x) { return x + 1; }"


class StubTarget:
    """Minimal stand-in for a Target, exposing only the arch expectation."""

    def __init__(self, expected_object_arch):
        self.expected_object_arch = expected_object_arch


class StubPatcherex:
    def __init__(self, expected_object_arch):
        self.target = StubTarget(expected_object_arch)


def check(expected_object_arch, obj_path):
    compiler = Compiler(StubPatcherex(expected_object_arch))
    with open(obj_path, "rb") as f:
        compiler.check_object_arch(ELFFile(f))


class TestObjectArchCheck:
    """
    Unit tests for the mismatch check itself, driven by prebuilt test binaries
    standing in for compiled objects (the check only reads the ELF header, so
    an executable works the same as a relocatable object).
    """

    def test_matching_arch_passes(self):
        check(
            ElfAmd64Linux.expected_object_arch,
            os.path.join(bin_location, "amd64/printf_nopie"),
        )

    def test_wrong_machine_raises(self):
        # An aarch64 object against an amd64 target: exactly the failure in #39.
        with pytest.raises(ObjectArchMismatchError, match="e_machine"):
            check(
                ElfAmd64Linux.expected_object_arch,
                os.path.join(bin_location, "aarch64/printf_nopie"),
            )

    def test_wrong_class_raises(self):
        # Same machine and endianness, wrong width: what bare `-m32`/`-m64`
        # gets wrong. mips64 vs mips are both EM_MIPS big-endian, so only
        # ei_class distinguishes them.
        with pytest.raises(ObjectArchMismatchError, match="ei_class"):
            check(
                ElfMips64Linux.expected_object_arch,
                os.path.join(bin_location, "mips/printf_nopie"),
            )

    def test_wrong_endianness_raises(self):
        # Same machine and width, opposite byte order.
        with pytest.raises(ObjectArchMismatchError, match="ei_data"):
            check(
                ElfPpc64Linux.expected_object_arch,
                os.path.join(bin_location, "ppc64le/printf_nopie"),
            )

    def test_no_expectation_skips_check(self):
        # A target that declares nothing keeps the old permissive behaviour.
        check(None, os.path.join(bin_location, "aarch64/printf_nopie"))

    @pytest.mark.parametrize("target_cls", [t for t, _ in TARGETS])
    def test_target_declares_expectation(self, target_cls):
        assert target_cls.expected_object_arch, (
            f"{target_cls.__name__} declares no expected_object_arch, so a "
            f"wrong-architecture patch would be applied silently"
        )

    def test_every_registered_target_declares_expectation(self):
        # Catches targets added later: without an expectation they fall back to
        # the permissive default and lose the mismatch check entirely.
        missing = sorted(
            t.__name__ for t in Target.target_classes if not t.expected_object_arch
        )
        assert not missing, (
            f"targets without expected_object_arch: {', '.join(missing)}"
        )

    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_expectation_matches_own_binary(self, target_cls, binary):
        # The declared expectation must describe the architecture the target
        # detects, otherwise the check would reject correct patches.
        check(target_cls.expected_object_arch, os.path.join(bin_location, binary))


class NoSymbolsAnalyzer:
    """Stands in for a binary analyzer; compile() only needs its symbols."""

    def get_all_symbols(self):
        return {}


class CompileOnlyPatcherex:
    """
    Enough of a Patcherex for Compiler.compile(): the target (for the arch
    expectation) and empty symbol sources. Avoids constructing a real binary
    analyzer, which is not what these tests are about.
    """

    def __init__(self, target_cls, binary_path):
        self.binary_path = binary_path
        self.target = target_cls(self, binary_path)
        self.symbols = {}
        self.binary_analyzer = NoSymbolsAnalyzer()
        # ClangArm post-processes its output through these.
        self.assembler = self.target.get_assembler(None)
        self.disassembler = self.target.get_disassembler(None)


class TestCompiledObjectArch:
    """
    End-to-end: each target's configured compiler must emit an object for that
    target's architecture. This is what actually fails on a non-x86 host when a
    target omits its triple -- and, with the check in place, what now raises
    instead of silently producing a patch in the wrong instruction set.
    """

    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_compiles_for_target_arch(self, target_cls, binary):
        p = CompileOnlyPatcherex(target_cls, os.path.join(bin_location, binary))
        compiler = p.target.get_compiler(None)
        # compile() runs check_object_arch internally, so a wrong-architecture
        # object raises here rather than being returned as bytes.
        assert compiler.compile(C_CODE)


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
        p = CompileOnlyPatcherex(
            ElfAmd64Linux, os.path.join(bin_location, "amd64/printf_nopie")
        )
        compiler = p.target.get_compiler(None)
        # mov eax, edi / add eax, 1 / ret
        assert compiler.compile(LLVM_IR_CODE, extension=".ll") == bytes.fromhex(
            "89f883c001c3"
        )

    def test_defaults_to_c(self):
        p = CompileOnlyPatcherex(
            ElfAmd64Linux, os.path.join(bin_location, "amd64/printf_nopie")
        )
        compiler = p.target.get_compiler(None)
        assert compiler.compile(C_CODE)

    def test_llvm_ir_rejected_as_c(self):
        # Guards against extension being ignored: IR fed to the C frontend must
        # not silently compile.
        p = CompileOnlyPatcherex(
            ElfAmd64Linux, os.path.join(bin_location, "amd64/printf_nopie")
        )
        compiler = p.target.get_compiler(None)
        with pytest.raises(subprocess.CalledProcessError):
            compiler.compile(LLVM_IR_CODE)


# References an extern global, which is what makes the compiler choose between
# materializing the address and loading it from the GOT.
EXTERN_DATA_C_CODE = (
    "extern char g_auth_token[128];\nchar *f(void) { return g_auth_token; }\n"
)

# The address the linker script would define g_auth_token at, standing in for
# a symbol read out of the target binary.
EXTERN_DATA_SYMBOLS = {"g_auth_token": 0x404100}


class NonPieTarget:
    """Stands in for a non-PIE target, which is where the GOT check applies."""

    def is_pie(self):
        return False


class NonPiePatcherex:
    def __init__(self):
        self.target = NonPieTarget()


class SymbolAnalyzer:
    """Stands in for a binary analyzer that reports one known global."""

    def get_all_symbols(self):
        return dict(EXTERN_DATA_SYMBOLS)


class ExternDataPatcherex(CompileOnlyPatcherex):
    """CompileOnlyPatcherex whose analyzer reports g_auth_token."""

    def __init__(self, target_cls, binary_path):
        super().__init__(target_cls, binary_path)
        self.binary_analyzer = SymbolAnalyzer()


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
        compiler = Compiler(NonPiePatcherex())
        with open(obj, "rb") as f:
            with pytest.raises(IndirectSymbolReferenceError, match="g_auth_token"):
                compiler.check_got_relocations(ELFFile(f), EXTERN_DATA_SYMBOLS)

    def test_symbols_we_do_not_define_are_ignored(self, tmp_path):
        # A GOT reference to a symbol the linker script does not define as an
        # absolute is none of this check's business.
        obj = self._compile_pic_object(tmp_path)
        compiler = Compiler(NonPiePatcherex())
        with open(obj, "rb") as f:
            compiler.check_got_relocations(ELFFile(f), {"unrelated": 0x1000})

    def test_pie_target_skips_check(self, tmp_path):
        # On a PIE binary the GOT is how patch code is meant to reach data.
        obj = self._compile_pic_object(tmp_path)

        class PiePatcherex:
            class target:
                @staticmethod
                def is_pie():
                    return True

        compiler = Compiler(PiePatcherex())
        with open(obj, "rb") as f:
            compiler.check_got_relocations(ELFFile(f), EXTERN_DATA_SYMBOLS)

    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_target_flags_avoid_got_indirection(self, target_cls, binary):
        # The real regression: each target's own compiler flags must resolve an
        # extern global to its address rather than through the GOT. compile()
        # runs check_got_relocations internally, so a target whose flags let PIC
        # codegen through raises here. The TARGETS binaries are all non-PIE, so
        # the check applies to every one of them.
        p = ExternDataPatcherex(target_cls, os.path.join(bin_location, binary))
        compiler = p.target.get_compiler(None)
        assert compiler.compile(EXTERN_DATA_C_CODE)


class TestPieDetection:
    """
    -fno-pic is correct only for non-PIE binaries: on a PIE target it makes the
    patch's own rodata references absolute, which is wrong once the patch is
    relocated into a cave.
    """

    # ppc64/ppc64le are excluded: they already emit R_PPC64_ADDR64 for extern
    # data, but reach it through the TOC (`ld 3, 0(3)`), which no compiler flag
    # changes -- the TOC is an ABI property, not a PIC mode. They are left on
    # their default flags rather than given a -fno-pic that would not help.
    FNO_PIC_TARGETS = [
        (t, b) for t, b in TARGETS if t not in (ElfPpc64Linux, ElfPpc64leLinux)
    ]

    @pytest.mark.parametrize("target_cls,binary", FNO_PIC_TARGETS)
    def test_nopie_binaries_get_fno_pic(self, target_cls, binary):
        p = CompileOnlyPatcherex(target_cls, os.path.join(bin_location, binary))
        assert not p.target.is_pie()
        assert "-fno-pic" in p.target.get_compiler(None)._compiler_flags

    @pytest.mark.parametrize(
        "target_cls,binary",
        [
            (ElfAmd64Linux, "amd64/replace_function_patch"),
            (ElfArmLinux, "armhf/replace_function_patch"),
        ],
    )
    def test_pie_binaries_keep_pic(self, target_cls, binary):
        p = CompileOnlyPatcherex(target_cls, os.path.join(bin_location, binary))
        assert p.target.is_pie()
        assert "-fno-pic" not in p.target.get_compiler(None)._compiler_flags
