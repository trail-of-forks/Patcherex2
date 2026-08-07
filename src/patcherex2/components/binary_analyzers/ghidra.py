from __future__ import annotations

import logging
import sys
import tempfile
from typing import final

from .binary_analyzer import BinaryAnalyzer, UnknownInstructionModeError

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

logger = logging.getLogger(__name__)


@final
class GhidraAnalyzer(BinaryAnalyzer):
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
            import ghidra.program.model.block
            import ghidra.program.model.symbol

            self.ghidra = ghidra
            self.bbm = ghidra.program.model.block.BasicBlockModel(self.currentProgram)
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

    @override
    @property
    def load_base(self) -> int:
        return self.currentProgram.getImageBase().getOffset()

    @override
    def normalize_addr(self, addr: int) -> int:
        if self.currentProgram.getRelocationTable().isRelocatable():
            addr -= self.load_base
        return addr

    @override
    def denormalize_addr(self, addr: int) -> int:
        if self.currentProgram.getRelocationTable().isRelocatable():
            addr += self.load_base
        return addr

    def _normalize_ghidra_addr(self, addr) -> int:
        return self.normalize_addr(addr.getOffset())

    def _to_ghidra_addr(self, addr: int):
        return self.flatapi.toAddr(hex(self.denormalize_addr(addr)))

    @override
    def mem_addr_to_file_offset(self, addr: int) -> int:
        ghidra_addr = self._to_ghidra_addr(addr)
        try:
            return self.currentProgram.getMemory().getAddressSourceInfo(ghidra_addr).getFileOffset()
        except Exception:  # noqa: BLE001
            raise ValueError(
                f"Memory address {hex(addr)} is not mapped to the file"
            ) from None

    @override
    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        from ghidra.util.task import (
            TaskMonitor,  # pyright: ignore[reportMissingModuleSource]
        )

        logger.info(f"getting basic block at {hex(addr)} with ghidra")
        ghidra_addr = self._to_ghidra_addr(addr)

        block = self.bbm.getFirstCodeBlockContaining(ghidra_addr, TaskMonitor.DUMMY)
        if block is None:
            raise ValueError(f"Cannot find block containing address {hex(addr)}")
        instrs = []
        ii = self.currentProgram.getListing().getInstructions(block, True)
        for i in ii:
            instrs.append(self._normalize_ghidra_addr(i.getAddress()))
        return {
            "start": self._normalize_ghidra_addr(block.getMinAddress()),
            "end": self._normalize_ghidra_addr(block.getMinAddress()) + block.getNumAddresses(),
            "size": block.getNumAddresses(),
            "instruction_addrs": instrs,
        }

    @override
    def get_instr_bytes_at(self, addr: int, num_instr=1):
        ghidra_addr = self._to_ghidra_addr(addr)
        instr = self.currentProgram.getListing().getInstructionContaining(ghidra_addr)
        if instr is None:
            return None
        b = bytes(instr.getBytes())
        for _i in range(1, num_instr):
            instr = instr.getNext()
            b = b"".join([b, bytes(instr.getBytes())])
        logger.info(
            f"got instr bytes of length {len(b)} for {num_instr} instrs at "
            f"{hex(addr)} with ghidra"
        )
        return b

    @override
    def get_unused_funcs(self) -> list[dict[str, int]]:
        logger.info("getting unused funcs with ghidra")
        fi = self.currentProgram.getListing().getFunctions(True)
        unused_funcs = []
        for f in fi:
            if not f.getSymbol().hasReferences():
                b = f.getBody()
                unused_funcs.append(
                    {
                        "addr": self._normalize_ghidra_addr(b.getMinAddress()),
                        "size": b.getNumAddresses(),
                    }
                )
        return unused_funcs

    @override
    def get_all_symbols(self) -> dict[str, int]:

        logger.info("getting all symbols with ghidra")
        symbols = {}
        for symbol in self.currentProgram.getSymbolTable().getAllSymbols(False):
            if not symbol.isPrimary():
                continue
            if (
                symbol.getSymbolType()
                == self.ghidra.program.model.symbol.SymbolType.FUNCTION
            ):
                continue
            address = symbol.getAddress()
            if not address.isMemoryAddress() or not symbol.getName():
                continue
            if (
                self.currentProgram.getListing().getDefinedDataContaining(address)
                is None
            ):
                continue
            symbols[symbol.getName()] = self._normalize_ghidra_addr(address)
        fi = self.currentProgram.getListing().getFunctions(True)
        for f in fi:
            # Preserve the first duplicate; the backend relies on its PLT ordering.
            if f.getName() in symbols:
                continue
            addr = self._normalize_ghidra_addr(f.getEntryPoint())
            if self.is_thumb(addr):
                addr += 1
            symbols[f.getName()] = addr
        return symbols

    @override
    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        if isinstance(name_or_addr, int):
            func = self.currentProgram.getListing().getFunctionContaining(self._to_ghidra_addr(name_or_addr))
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
            "addr": self._normalize_ghidra_addr(b.getMinAddress()),
            "size": b.getNumAddresses(),
        }

    def thumb_mode(self, addr: int) -> bool | None:
        """Return the Ghidra ARM mode, or None when it is unknown."""
        register = self.currentProgram.getRegister("TMode")
        if register is None:
            return False

        value = self.currentProgram.getProgramContext().getRegisterValue(
            register, self._to_ghidra_addr(addr)
        )
        if value is None or not value.hasValue():
            logger.info(f"address {hex(addr)} has no TMode value in ghidra")
            return None

        is_thumb = value.unsignedValueIgnoreMask.intValue() == 1
        logger.info(
            f"address {hex(addr)} {'is' if is_thumb else 'is not'} thumb from ghidra"
        )
        return is_thumb

    @override
    def is_thumb(self, addr: int) -> bool:
        mode = self.thumb_mode(addr)
        if mode is None:
            raise UnknownInstructionModeError(
                f"Cannot determine ARM instruction mode at {hex(addr)}"
            )
        return mode
