from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.assemblers.keystone import Keystone, keystone
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.clang import Clang
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.utils.utils import Utils
from .target import Target


class ElfPpcLinux(Target):
    NOP_BYTES = b"\x60\x00\x00\x00"
    NOP_SIZE = 4
    JMP_ASM = "b {dst}"
    JMP_SIZE = 4

    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\x00\x14", 0x12
            ):  # EM_PPC
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return Keystone(
                self.p,
                keystone.KS_ARCH_PPC,
                keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_PPC32,
            )
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return Clang(self.p, compiler_flags=["-target", "powerpc-linux-gnu"])
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            cs = Capstone(
                capstone.CS_ARCH_PPC, capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_32
            )
            # NOTE: Doing this because keystone expects registers to just be numbers
            cs.cs.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME
            return cs
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "pyelftools"
        if binfmt_tool == "pyelftools":
            return ELF(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path)
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()

    # Emits a thunk which calculates the base address
    # by subtracting the patch insertion address from
    # the current pc and stores it in the given register
    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        assert "%r" in base_reg
        scratch_reg1 = "%r4" if base_reg == "%r3" else "%r3"
        scratch_reg2 = "%r12" if base_reg == "%r11" else "%r11"

        # add 12 since base_reg will contain
        # the addr + 12
        thunk_loc = insert_addr + 12
        thunk_l = 0xFFFF & thunk_loc
        thunk_h = 0xFFFF & (thunk_loc >> 16)
        thunk_instrs = f"""
        stwu %r1, -8(%r1)
        stw {scratch_reg2}, 4(%r1)
        stw {scratch_reg1}, 0(%r1)
        mflr {scratch_reg2}
        bl lb
        lb:
        mflr {base_reg}
        lis {scratch_reg1}, {thunk_h}
        ori {scratch_reg1}, {scratch_reg1}, {thunk_l}
        sub {base_reg}, {base_reg}, {scratch_reg1}
        mtlr {scratch_reg2}
        lwz {scratch_reg1}, 0(%r1)
        lwz {scratch_reg2}, 4(%r1)
        addi %r1, %r1, 8
        """

        return thunk_instrs
