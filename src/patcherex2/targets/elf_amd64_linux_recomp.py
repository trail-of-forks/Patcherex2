from ..components.binary_analyzers.angr import AngrAnalyzer
from ..components.binary_analyzers.ghidra import GhidraAnalyzer
from ..components.binary_analyzers.ida import IDAAnalyzer
from ..components.compilers.llvm_recomp import LLVMRecomp
from .elf_amd64_linux import ElfAmd64Linux


class ElfAmd64LinuxRecomp(ElfAmd64Linux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_compiler(self, compiler):
        compiler = compiler or "llvm_recomp"
        if compiler == "llvm_recomp":
            return LLVMRecomp(self.p, compiler_flags=["-target", "x86_64-linux-gnu"])
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer, **kwargs):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return AngrAnalyzer(self.binary_path, **kwargs)
        if binary_analyzer == "ghidra":
            return GhidraAnalyzer(self.binary_path, **kwargs)
        if binary_analyzer == "ida":
            return IDAAnalyzer(self.binary_path, **kwargs)
        raise NotImplementedError()
