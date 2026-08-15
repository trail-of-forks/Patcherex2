from __future__ import annotations

import logging
import tempfile

from .binary_analyzer import BinaryAnalyzer

logger = logging.getLogger(__name__)


class Ghidra(BinaryAnalyzer):
    def __init__(self, binary_path: str, language: str | None = None, **kwargs):
        import pyghidra

        self.temp_proj_dir_ctx = tempfile.TemporaryDirectory()
        self.temp_proj_dir = self.temp_proj_dir_ctx.name
        self.project = None
        self.load_results = None
        self.program_consumer = None
        self.currentProgram = None
        self.flatapi = None

        try:
            pyghidra.start()
            self.project = pyghidra.open_project(
                self.temp_proj_dir, "patcherex2", create=True
            )
            loader = pyghidra.program_loader().project(self.project)
            if language is not None:
                loader = loader.language(language)
            self.load_results = loader.source(binary_path).load()

            from ghidra.program.flatapi import FlatProgramAPI
            from java.lang import Object

            self.program_consumer = Object()
            self.currentProgram = self.load_results.getPrimary().getDomainObject(
                self.program_consumer
            )
            pyghidra.analyze(self.currentProgram)
            self.flatapi = FlatProgramAPI(self.currentProgram)

            import ghidra

            self.ghidra = ghidra
            self.bbm = self.ghidra.program.model.block.BasicBlockModel(
                self.currentProgram
            )
        except BaseException:
            self.shutdown()
            raise

    def shutdown(self):
        current_program = self.currentProgram
        program_consumer = self.program_consumer
        self.currentProgram = None
        self.program_consumer = None
        self.flatapi = None
        try:
            if current_program is not None and program_consumer is not None:
                current_program.release(program_consumer)
        finally:
            load_results = self.load_results
            self.load_results = None
            try:
                if load_results is not None:
                    load_results.close()
            finally:
                project = self.project
                self.project = None
                try:
                    if project is not None:
                        project.close()
                finally:
                    temp_proj_dir_ctx = self.temp_proj_dir_ctx
                    self.temp_proj_dir_ctx = None
                    self.temp_proj_dir = None
                    if temp_proj_dir_ctx is not None:
                        temp_proj_dir_ctx.cleanup()

    def normalize_addr(self, addr):
        addr = addr.getOffset()
        if self.currentProgram.getRelocationTable().isRelocatable():
            addr -= self.currentProgram.getImageBase().getOffset()
        return addr

    def denormalize_addr(self, addr):
        if self.currentProgram.getRelocationTable().isRelocatable():
            addr += self.currentProgram.getImageBase().getOffset()
        return self.flatapi.toAddr(hex(addr))

    def mem_addr_to_file_offset(self, addr: int) -> int:
        addr = self.denormalize_addr(addr)
        try:
            return (
                self.currentProgram.getMemory()
                .getAddressSourceInfo(addr)
                .getFileOffset()
            )
        except Exception:  # noqa: BLE001
            raise ValueError("Can't get file offset for addr") from None

    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        logger.info(f"getting basic block at 0x{addr} with ghidra")
        addr = self.denormalize_addr(addr)

        block = self.bbm.getFirstCodeBlockContaining(
            addr, self.ghidra.util.task.TaskMonitor.DUMMY
        )
        if block is None:
            raise ValueError(f"Cannot find block containing address 0x{addr}")
        instrs = []
        ii = self.currentProgram.getListing().getInstructions(block, True)
        for i in ii:
            instrs.append(self.normalize_addr(i.getAddress()))
        return {
            "start": self.normalize_addr(block.getMinAddress()),
            "end": self.normalize_addr(block.getMinAddress()) + block.getNumAddresses(),
            "size": block.getNumAddresses(),
            "instruction_addrs": instrs,
        }

    def get_instr_bytes_at(self, addr: int, num_instr=1):
        addr = self.denormalize_addr(addr)
        instr = self.currentProgram.getListing().getInstructionContaining(addr)
        if instr is None:
            return None
        b = instr.getBytes()
        for _i in range(1, num_instr):
            instr = instr.getNext()
            b = b"".join([b, instr.getBytes()])
        logger.info(
            f"got instr bytes of length {len(b)} for {num_instr} instrs at 0x{addr} with ghidra"
        )
        return b

    def get_unused_funcs(self) -> list[dict[str, int]]:
        logger.info("getting unused funcs with ghidra")
        fi = self.currentProgram.getListing().getFunctions(True)
        unused_funcs = []
        for f in fi:
            if not f.getSymbol().hasReferences():
                b = f.getBody()
                unused_funcs.append(
                    {
                        "addr": self.normalize_addr(b.getMinAddress()),
                        "size": b.getNumAddresses(),
                    }
                )
        return unused_funcs

    def get_all_symbols(self) -> dict[str, int]:
        logger.info("getting all symbols with ghidra")
        symbols = {}
        # si = self.currentProgram.getSymbolTable().getAllSymbols(True)
        # for s in si:
        #     if not s.isPrimary():
        #         continue
        #     symbols[s.getName()] = self.normalize_addr(
        #         s.getAddress().getOffset())
        fi = self.currentProgram.getListing().getFunctions(True)
        for f in fi:
            if f.getName() in symbols:
                continue
            symbols[f.getName()] = self.normalize_addr(f.getEntryPoint())
            if self.is_thumb(symbols[f.getName()]):
                symbols[f.getName()] += 1
        return symbols

    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        if isinstance(name_or_addr, int):
            name_or_addr = self.denormalize_addr(name_or_addr)
            func = self.currentProgram.getListing().getFunctionContaining(name_or_addr)
            if func is None:
                return None
        elif isinstance(name_or_addr, str):
            funcs = self.currentProgram.getListing().getGlobalFunctions(name_or_addr)
            if len(funcs) == 0:
                return None
            func = funcs[0]
        else:
            raise TypeError(f"Invalid type for name_or_addr: {type(name_or_addr)}")

        b = func.getBody()
        return {
            "addr": self.normalize_addr(b.getMinAddress()),
            "size": b.getNumAddresses(),
        }

    def is_thumb(self, addr: int) -> bool:
        addr = self.denormalize_addr(addr)
        r = self.currentProgram.getRegister("TMode")
        if r is None:
            return False
        v = self.currentProgram.getProgramContext().getRegisterValue(r, addr)
        t = v.unsignedValueIgnoreMask.intValue() == 1
        logger.info(f"address 0x{addr} {'is' if t else 'is not'} thumb from ghidra")
        return t
