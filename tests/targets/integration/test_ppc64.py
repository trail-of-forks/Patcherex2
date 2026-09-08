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
from patcherex2.targets import ELF_PPC64_LINUX
from tests.support.integration import IntegrationTestMixin
from tests.support.paths import TEST_BINARIES

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests(IntegrationTestMixin):
    target = ELF_PPC64_LINUX
    bin_location: str
    binary_analyzer: str

    @pytest.fixture(autouse=True, scope="class", params=["angr", "ghidra"])
    def setup(self, request):
        request.cls.bin_location = str(TEST_BINARIES / "ppc64")
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x88F, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0xB74, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x1000088F, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0xB74, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x1000076C, "subi 4, 4, 0x7674"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0xA4C, "subi 4, 4, 0x738C"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            li 0, 0x4
            li 3, 1
            lis 4, 0x1000088f@h
            addi 4, 4, 0x1000088f@l
            li 5, 0x3
            sc
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x10000774, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            li 0, 0x4
            li 3, 1
            addi 4, 4, 0x1
            li 5, 0x3
            sc
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0xA54, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            li 3, 0x32
            li 0, 0x1
            sc
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x10000774, "b <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            li 3, 0x32
            li 0, 0x1
            sc
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0xA54, "b <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x10000890, num_bytes=4),
            ],
            expected_output=b"H\x60",
            expected_return_code=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0xB78, num_bytes=4),
            ],
            expected_output=b"H\x60",
            expected_return_code=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x1000088F, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0xB77, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_insert_data_patch_nopie(self):
        tlen = 5
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = f"""
            li 0, 0x4
            li 3, 0x1
            lis 4, <added_data>@h
            addi 4, 4, <added_data>@l
            li 5, {hex(tlen)}
            sc
        """
        p2 = InsertInstructionPatch(0x10000774, instrs)
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
            li 0, 0x4
            li 3, 0x1
            lis 4, <added_data>@h
            addi 4, 4, <added_data>@l
            li 5, {hex(tlen)}
            sc
        """
        p2 = InsertInstructionPatch(0xA54, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_return_code=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x10000890, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0xB78, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0xB44, code)],
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
            [ModifyFunctionPatch(0xBEC, code)],
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
            [ModifyFunctionPatch(0xBEC, code)],
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
                ModifyFunctionPatch(0xD2C, replace_code),
            ],
            expected_output=b"2121212121",
            expected_return_code=0,
        )
