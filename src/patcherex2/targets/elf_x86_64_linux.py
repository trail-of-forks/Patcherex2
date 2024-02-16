from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.assemblers.keystone import Keystone, keystone
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.clang import Clang
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.utils.utils import Utils
from .target import Target


class ElfX8664Linux(Target):
    NOP_BYTES = b"\x90"
    NOP_SIZE = 1
    JMP_ASM = "jmp {dst}"
    JMP_SIZE = 6

    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\x3e\x00", 0x12
            ):  # EM_X86_64
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return Keystone(
                self.p,
                keystone.KS_ARCH_X86,
                keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_64,
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
            return Clang(self.p)
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return Capstone(
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_64,
            )
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

    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        scratch_reg = "r13" if base_reg == "r12" else "r12"
        thunk_loc = insert_addr + 5
        # move past the red zone so we
        # don't clobber any locals
        thunk_instrs = f"""
        sub rsp, 128
        push {scratch_reg}
        call lb:
        lb:
        pop {base_reg}
        mov {scratch_reg}, {thunk_loc}
        sub {base_reg}, {scratch_reg}
        pop {scratch_reg}
        add rsp, 128
        """
        return thunk_instrs
