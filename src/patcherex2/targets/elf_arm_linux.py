from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.assemblers.keystone_arm import KeystoneArm
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.clang_arm import ClangArm
from ..components.disassemblers.capstone_arm import CapstoneArm
from ..components.utils.utils import Utils
from .target import Target


class ElfArmLinux(Target):
    NOP_BYTES = b"\x00\xF0\x20\xE3"  # TODO: thumb
    NOP_SIZE = 4
    JMP_ASM = "b {dst}"
    JMP_SIZE = 4

    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\x28\x00", 0x12
            ):  # EM_ARM
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return KeystoneArm(self.p)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return ClangArm(self.p, compiler_flags=["-target", "arm-linux-gnueabihf"])
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return CapstoneArm(self.p)
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
        scratch_reg = "r4" if base_reg == "r3" else "r3"
        # need to add 4/8 here since pc
        # points to the next instruction
        thunk_loc = insert_addr + (4 if is_thumb else 8)
        thunk_l = 0xFFFF & thunk_loc
        thunk_h = 0xFFFF & (thunk_loc >> 16)
        thunk_instrs = f"""
        mov {base_reg}, pc
        push {{{scratch_reg}}}
        movw {scratch_reg}, #{thunk_l}
        movt {scratch_reg}, #{thunk_h}
        sub {base_reg}, {scratch_reg}
        pop {{{scratch_reg}}}
        """
        return thunk_instrs

    @staticmethod
    def emit_load_addr(addr, reg_name=None):
        # place holder register to get size
        if reg_name is None:
            reg_name = "r2"
        addr_l = 0xFFFF & addr
        addr_h = 0xFFFF & (addr >> 16)
        load_instrs = f"""
        movw {reg_name}, #{addr_l}
        movt {reg_name}, #{addr_h}
        """
        return load_instrs
