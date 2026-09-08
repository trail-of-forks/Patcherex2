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
from patcherex2.targets import ELF_S390X_LINUX
from tests.support.integration import IntegrationTestMixin
from tests.support.paths import TEST_BINARIES

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests(IntegrationTestMixin):
    target = ELF_S390X_LINUX
    bin_location: str
    binary_analyzer: str

    # @pytest.fixture(autouse=True, scope="class", params=["angr", "ghidra"])
    @pytest.fixture(autouse=True, scope="class", params=["angr"])
    def setup(self, request):
        request.cls.bin_location = str(TEST_BINARIES / "s390x")
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x648, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x7E8, b"No", addr_type=AddressType.FILE)],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x1000648, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x7E8, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x10005F0, "larl %r3, 0x100064C"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0x790, "larl %r3, 0x7EC"),
            ],
            expected_output=b"%s",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            larl %r2, 0x1000648
            brasl %r14, <printf>
            larl %r2, 0x1000648
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x10005FC, instrs)],
            expected_output=b"HiHi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            larl %r2, 0x7e8
            brasl %r14, <printf>
            larl %r2, 0x7e8
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x7A2, instrs)],
            expected_output=b"HiHi",
            expected_return_code=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            lghi %r2, 0x32
            br %r14
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x10005FC, "j <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            lghi %r2, 0x32
            br %r14
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x79C, "j <return_0x32>"),
            ],
            expected_return_code=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x1000649, num_bytes=2),
            ],
            expected_output=b"H\x07",
            expected_return_code=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x7E9, num_bytes=2),
            ],
            expected_output=b"H\x07",
            expected_return_code=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x1000648, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x7E8, b"No")],
            expected_output=b"No",
            expected_return_code=0,
        )

    def test_insert_data_patch_nopie(self):
        tlen = 5
        p1 = InsertDataPatch("added_data", b"A" * tlen + b"\x00")
        instrs = """
            larl %r2, <added_data>
            brasl %r14, <printf>
            larl %r2, 0x1000648
        """
        p2 = InsertInstructionPatch(0x10005FC, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_return_code=0,
        )

    def test_insert_data_patch_pie(self):
        tlen = 5
        p1 = InsertDataPatch("added_data", b"A" * tlen + b"\x00")
        instrs = """
            larl %r2, <added_data>
            brasl %r14, <printf>
            larl %r2, 0x7E8
        """
        p2 = InsertInstructionPatch(0x79C, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_return_code=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x1000649, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x7E9, 1)],
            expected_output=b"H",
            expected_return_code=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x7D0, code)],
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
            [ModifyFunctionPatch(0x890, code)],
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
            [ModifyFunctionPatch(0x890, code)],
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
                ModifyFunctionPatch(0x780, replace_code),
            ],
            expected_output=b"2121212121",
            expected_return_code=0,
        )
