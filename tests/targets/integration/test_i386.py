import logging

import pytest

from patcherex2 import (
    AddressType,
    InsertDataPatch,
    InsertFunctionPatch,
    InsertInstructionPatch,
    ModifyDataPatch,
    ModifyFunctionPatch,
    ModifyInstructionPatch,
    ModifyRawBytesPatch,
    RemoveDataPatch,
    RemoveInstructionPatch,
)
from patcherex2.targets import ELF_X86_LINUX
from tests.support.integration import IntegrationTestMixin
from tests.support.paths import TEST_BINARIES

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests(IntegrationTestMixin):
    target = ELF_X86_LINUX
    bin_location: str
    binary_analyzer: str

    @pytest.fixture(autouse=True, scope="class", params=["angr", "ghidra"])
    def setup(self, request):
        request.cls.bin_location = str(TEST_BINARIES / "x86")
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x2008, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x200B, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x804A008, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x200B, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x8049192, "lea edx, [0x804a00b]"),
                ModifyInstructionPatch(0x8049198, "push edx"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0x11C0, "lea eax, [ebx + 0xffffe008]"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_modify_instruction_patch2_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyInstructionPatch(0x80491A0, "mov eax, 0x0")],
            expected_output=b"",
            expected_return_code=0,
        )

    def test_modify_instruction_patch2_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyInstructionPatch(0x11C9, "mov eax, 0x0")],
            expected_output=b"",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            mov eax, 0x4
            mov ebx, 0x1
            lea ecx, [0x804a008]
            mov edx, 0x3
            int 0x80
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x80491A7, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            lea ecx, [ebx + 0xffffe00b]
            mov eax, 0x4
            mov ebx, 0x1
            mov edx, 0x3
            int 0x80
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x11D2, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            mov eax, 0x32
            leave
            ret
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x80491A7, "jmp <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            mov eax, 0x32
            leave
            ret
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x11D2, "jmp <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x804A009, num_bytes=1),
            ],
            expected_output=b"H\x90",
            expected_return_code=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x200C, num_bytes=1),
            ],
            expected_output=b"H\x90",
            expected_return_code=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x804A008, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x200B, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_insert_data_patch_nopie(self):
        tlen = 5
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = f"""
            mov eax, 0x4
            mov ebx, 0x1
            lea ecx, [<added_data>]
            mov edx, {hex(tlen)}
            int 0x80
        """
        p2 = InsertInstructionPatch(0x80491A7, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_return_code=0,
        )

    @pytest.mark.xfail(reason="PIE data insertion is not supported", strict=False)
    def test_insert_data_patch_pie(self):
        tlen = 5
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = f"""
            mov eax, 0x4
            mov ebx, 0x1
            lea edx, [here]
            here: and edx, 0xffff0000
            lea ecx, [edx + <added_data>]
            mov edx, {hex(tlen)}
            int 0x80
        """
        p2 = InsertInstructionPatch(0x11D2, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_return_code=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x804A009, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x200C, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_replace_function_patch_nopie(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x119D, code)],
            expected_output=b"70707070",
            expected_return_code=0,
        )

    @pytest.mark.xfail(reason="CLE relocation support is incomplete", strict=False)
    def test_replace_function_patch_with_function_reference(self):
        code = """
        extern int add(int, int);
        extern int subtract(int, int);
        int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = subtract(c, a)) if(b <= 0) return c; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x11C9, code)],
            expected_output=b"-21-21",
            expected_return_code=0,
        )

    @pytest.mark.xfail(reason="CLE relocation support is incomplete", strict=False)
    def test_replace_function_patch_with_function_reference_and_rodata(self):
        code = """
        extern int printf(const char *format, ...);
        int multiply(int a, int b){ printf("%sWorld %s %s %s %d\\n", "Hello ", "Hello ", "Hello ", "Hello ", a * b);printf("%sWorld\\n", "Hello "); return a * b; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x11C9, code)],
            expected_output=b"Hello World Hello  Hello  Hello  21\nHello World\n2121",
            expected_return_code=0,
        )

    @pytest.mark.xfail(reason="CLE relocation support is incomplete", strict=False)
    def test_insert_function_patch(self):
        insert_code = """
        int min(int a, int b) { return (a < b) ? a : b; }
        """
        replace_code = """
        extern int min(int, int);
        int max(int a, int b) { return min(a, b); }
        """
        self.run_one(
            "replace_function_patch",
            [
                InsertFunctionPatch("min", insert_code),
                ModifyFunctionPatch(0x1261, replace_code),
            ],
            expected_output=b"2121212121",
            expected_return_code=0,
        )
