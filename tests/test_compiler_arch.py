import os
from types import SimpleNamespace

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2.components.compilers.compiler import (
    Compiler,
    ObjectArchMismatchError,
    UnsupportedRelocationError,
)
from patcherex2.targets import (
    ElfAArch64Linux,
    ElfAmd64Linux,
    ElfAmd64LinuxRecomp,
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

BIN_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "test_binaries"
)
EXTERN_DATA_CODE = (
    "extern char g_auth_token[128]; char *f(void) { return g_auth_token; }"
)
DEFAULT_VISIBILITY_EXTERN_DATA_CODE = """
extern char g_auth_token[128] __attribute__((visibility("default")));
char *f(void) { return g_auth_token; }
"""
C_CODE = "int f(int x) { return x + 1; }"
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
RECOMP_TARGETS = [
    (ElfAmd64LinuxRecomp, "amd64/printf_nopie"),
    (ElfAmd64LinuxRecomp, "amd64/printf_pie"),
]


def binary_arch(path):
    with open(path, "rb") as binary:
        elf = ELFFile(binary)
        return {
            "e_machine": elf.header["e_machine"],
            "ei_class": elf.header["e_ident"]["EI_CLASS"],
            "ei_data": elf.header["e_ident"]["EI_DATA"],
        }


def target_arch(target_cls, binary):
    target = target_cls(None, os.path.join(BIN_LOCATION, binary))
    return target.get_archinfo(None).elf_arch


def check_object_arch(expected, path):
    patcherex = SimpleNamespace(archinfo=SimpleNamespace(elf_arch=expected))
    compiler = Compiler(patcherex)
    with open(path, "rb") as binary:
        compiler.check_object_arch(ELFFile(binary))


class TestObjectArchCheck:
    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_archinfo_matches_target_binary(self, target_cls, binary):
        path = os.path.join(BIN_LOCATION, binary)
        assert target_arch(target_cls, binary) == binary_arch(path)

    def test_wrong_machine_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="e_machine"):
            check_object_arch(
                target_arch(ElfAmd64Linux, "amd64/printf_nopie"),
                os.path.join(BIN_LOCATION, "aarch64/printf_nopie"),
            )

    def test_wrong_class_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="ei_class"):
            check_object_arch(
                target_arch(ElfMips64Linux, "mips64/printf_nopie"),
                os.path.join(BIN_LOCATION, "mips/printf_nopie"),
            )

    def test_wrong_endianness_raises(self):
        with pytest.raises(ObjectArchMismatchError, match="ei_data"):
            check_object_arch(
                target_arch(ElfPpc64Linux, "ppc64/printf_nopie"),
                os.path.join(BIN_LOCATION, "ppc64le/printf_nopie"),
            )

    def test_every_registered_target_has_archinfo(self):
        missing = []
        for target_cls in Target.target_classes:
            try:
                archinfo = target_cls(None, "").get_archinfo(None)
            except NotImplementedError:
                continue
            if not getattr(archinfo, "elf_arch", None):
                missing.append(target_cls.__name__)
        assert not missing, f"targets without archinfo.elf_arch: {missing}"


class TestPicCompilerFlags:
    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_fixed_targets_disable_pic(self, target_cls, binary):
        patcherex = CompileOnlyPatcherex(target_cls, os.path.join(BIN_LOCATION, binary))
        compiler = patcherex.target.get_compiler(None)
        expected = ["-fno-pic"]
        if target_cls in (ElfMips64Linux, ElfMips64elLinux):
            expected.append("-mno-abicalls")

        assert compiler.pic_compiler_flags() == expected

    def test_pie_targets_keep_pic(self):
        patcherex = CompileOnlyPatcherex(
            ElfAmd64Linux, os.path.join(BIN_LOCATION, "amd64/printf_pie")
        )
        compiler = patcherex.target.get_compiler(None)

        assert compiler.pic_compiler_flags() == []

    def test_ppc64_toc_relocation_fails_loudly(self):
        binary = os.path.join(BIN_LOCATION, "ppc64/printf_nopie")
        patcherex = CompileOnlyPatcherex(ElfPpc64Linux, binary)
        patcherex.symbols["g_auth_token"] = 0x404100

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patcherex.target.get_compiler(None).compile(EXTERN_DATA_CODE)


class CompileOnlyPatcherex:
    def __init__(self, target_cls, binary_path):
        self.binary_path = binary_path
        self.target = target_cls(self, binary_path)
        self.archinfo = self.target.get_archinfo(None)
        self.allocation_manager = self.target.get_allocation_manager(None)
        self.binfmt_tool = self.target.get_binfmt_tool(None)
        self.symbols = {}
        self.binary_analyzer = SimpleNamespace(get_all_symbols=dict)
        self.assembler = self.target.get_assembler(None)
        self.disassembler = self.target.get_disassembler(None)


class TestCompiledObjectArch:
    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_compiles_for_target_arch(self, target_cls, binary):
        path = os.path.join(BIN_LOCATION, binary)
        patcherex = CompileOnlyPatcherex(target_cls, path)
        assert patcherex.target.get_compiler(None).compile(C_CODE)

    @pytest.mark.parametrize("target_cls,binary", RECOMP_TARGETS)
    def test_recomp_compiles_for_target_arch(self, target_cls, binary):
        path = os.path.join(BIN_LOCATION, binary)
        patcherex = CompileOnlyPatcherex(target_cls, path)
        assert patcherex.target.get_compiler(None).compile(C_CODE)

    @pytest.mark.parametrize(
        "target_cls",
        [ElfAmd64Linux, ElfAmd64LinuxRecomp],
    )
    def test_pie_compiles_direct_fixed_symbol_reference(self, target_cls):
        path = os.path.join(BIN_LOCATION, "amd64/printf_pie")
        patcherex = CompileOnlyPatcherex(target_cls, path)
        patcherex.symbols["g_auth_token"] = 0x2007

        compiled = patcherex.target.get_compiler(None).compile(EXTERN_DATA_CODE)
        instructions = patcherex.disassembler.disassemble(compiled)

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
        "target_cls",
        [ElfAmd64Linux, ElfAmd64LinuxRecomp],
    )
    def test_pie_rejects_residual_got_reference(self, target_cls):
        path = os.path.join(BIN_LOCATION, "amd64/printf_pie")
        patcherex = CompileOnlyPatcherex(target_cls, path)
        patcherex.symbols["g_auth_token"] = 0x2007

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patcherex.target.get_compiler(None).compile(
                DEFAULT_VISIBILITY_EXTERN_DATA_CODE
            )

    def test_fixed_recomp_embeds_absolute_external_data_address(self):
        path = os.path.join(BIN_LOCATION, "amd64/printf_nopie")
        patcherex = CompileOnlyPatcherex(ElfAmd64LinuxRecomp, path)
        patcherex.symbols["g_auth_token"] = 0x404100

        compiled = patcherex.target.get_compiler(None).compile(EXTERN_DATA_CODE)
        instructions = patcherex.disassembler.disassemble(compiled)

        assert any("0x404100" in instruction["op_str"] for instruction in instructions)

    def test_fixed_recomp_rejects_forced_pic(self):
        path = os.path.join(BIN_LOCATION, "amd64/printf_nopie")
        patcherex = CompileOnlyPatcherex(ElfAmd64LinuxRecomp, path)
        patcherex.symbols["g_auth_token"] = 0x404100

        with pytest.raises(UnsupportedRelocationError, match="g_auth_token"):
            patcherex.target.get_compiler(None).compile(
                EXTERN_DATA_CODE, extra_compiler_flags=["-fPIC"]
            )
