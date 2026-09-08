# ruff: noqa: N802 - protocols intentionally mirror Ghidra's Java API.
from __future__ import annotations

import logging
import sys
import tempfile
from collections.abc import Generator, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Protocol, cast, final

from patcherex2.components.binary_analyzer import (
    BasicBlock,
    BinaryAnalyzer,
    FunctionInfo,
    UnknownInstructionModeError,
)

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.binary_analyzer.symbol import (
    ExternalSymbol,
    MappedSymbol,
    Symbol,
)

logger = logging.getLogger(__name__)


class GhidraAddressApi(Protocol):
    def getOffset(self) -> int: ...


class GhidraFlatProgramApi(Protocol):
    def toAddr(self, value: str) -> GhidraAddressApi: ...


class GhidraBasicBlockModelApi(Protocol):
    def getFirstCodeBlockContaining(
        self,
        address: GhidraAddressApi,
        monitor: GhidraTaskMonitorApi,
        /,
    ) -> Any: ...


class GhidraTaskMonitorApi(Protocol):
    """Marker protocol for Ghidra task monitors."""


class GhidraProgramApi(Protocol):
    def getImageBase(self) -> GhidraAddressApi: ...

    def getRelocationTable(self) -> Any: ...

    def getMemory(self) -> Any: ...

    def getListing(self) -> Any: ...

    def getSymbolTable(self) -> Any: ...

    def getRegister(self, name: str) -> Any: ...

    def getProgramContext(self) -> Any: ...

    def release(self, consumer: Any) -> None: ...


class GhidraAnalysis:
    """Objects created by a Ghidra API for one analysis session."""

    def __init__(
        self,
        *,
        program: GhidraProgramApi,
        flat_program_api: GhidraFlatProgramApi,
        basic_block_model: GhidraBasicBlockModelApi,
        task_monitor: GhidraTaskMonitorApi,
    ) -> None:
        self.program = program
        self.flat_program_api = flat_program_api
        self.basic_block_model = basic_block_model
        self.task_monitor = task_monitor


class GhidraApi(Protocol):
    """Open and own the resources needed for a Ghidra analysis."""

    def load_binary(
        self,
        binary_path: str,
        language: str | None,
    ) -> AbstractContextManager[GhidraAnalysis]: ...


@final
class PyGhidraApi:
    """Adapt pyghidra's project and program lifetimes to ``GhidraApi``."""

    @contextmanager
    def load_binary(
        self,
        binary_path: str,
        language: str | None,
    ) -> Generator[GhidraAnalysis]:
        import pyghidra

        with tempfile.TemporaryDirectory() as project_directory:
            if not pyghidra.started():
                pyghidra.start()
            with pyghidra.open_project(project_directory, "patcherex2", create=True) as project:
                loader = pyghidra.program_loader().project(project)
                if language is not None:
                    loader = loader.language(language)

                # Java modules are loaded by JPype after JVM startup, with no Python source.
                from ghidra.program.flatapi import (  # pyright: ignore[reportMissingModuleSource]
                    FlatProgramAPI,
                )
                from ghidra.program.model.block import (  # pyright: ignore[reportMissingModuleSource]
                    BasicBlockModel,
                )

                with loader.source(binary_path).load() as load_results:
                    program = load_results.getPrimaryDomainObject(load_results)
                    try:
                        monitor = pyghidra.task_monitor()
                        pyghidra.analyze(program, monitor)
                        yield GhidraAnalysis(
                            program=program,
                            flat_program_api=FlatProgramAPI(program, monitor),
                            basic_block_model=BasicBlockModel(program),
                            task_monitor=monitor,
                        )
                    finally:
                        program.release(load_results)


DEFAULT_GHIDRA_API = PyGhidraApi()


@final
class GhidraAnalyzer(BinaryAnalyzer):
    #: Synthetic block the analyzer appends past the end of the image to
    #: anchor names whose definitions live elsewhere.
    EXTERNAL_BLOCK = "EXTERNAL"

    def __init__(
        self,
        program: GhidraProgramApi,
        flat_program_api: GhidraFlatProgramApi,
        basic_block_model: GhidraBasicBlockModelApi,
        task_monitor: GhidraTaskMonitorApi,
    ) -> None:
        self.program = program
        self.flat_program_api = flat_program_api
        self.basic_block_model = basic_block_model
        self.task_monitor = task_monitor

    @classmethod
    @contextmanager
    def load_binary(
        cls,
        binary_path: str,
        language: str | None = None,
        *,
        api: GhidraApi = DEFAULT_GHIDRA_API,
    ) -> Generator[GhidraAnalyzer]:
        """Load and analyze a binary for the lifetime of a context manager."""
        with api.load_binary(binary_path, language) as analysis:
            yield cls(
                analysis.program,
                analysis.flat_program_api,
                analysis.basic_block_model,
                analysis.task_monitor,
            )

    @property
    @override
    def load_base(self) -> int:
        return self.program.getImageBase().getOffset()

    @override
    def normalize_addr(self, addr: int) -> int:
        if self.program.getRelocationTable().isRelocatable():
            addr -= self.load_base
        return addr

    @override
    def denormalize_addr(self, addr: int) -> int:
        if self.program.getRelocationTable().isRelocatable():
            addr += self.load_base
        return addr

    def _normalize_ghidra_addr(self, addr: GhidraAddressApi) -> int:
        return self.normalize_addr(addr.getOffset())

    def _to_ghidra_addr(self, addr: int) -> GhidraAddressApi:
        return self.flat_program_api.toAddr(hex(self.denormalize_addr(addr)))

    @override
    def mem_addr_to_file_offset(self, addr: int) -> int:
        ghidra_addr = self._to_ghidra_addr(addr)
        try:
            return self.program.getMemory().getAddressSourceInfo(ghidra_addr).getFileOffset()
        except Exception:  # noqa: BLE001
            raise ValueError(f"Memory address {hex(addr)} is not mapped to the file") from None

    @override
    def get_basic_block(self, addr: int) -> BasicBlock:
        logger.info(f"getting basic block at {hex(addr)} with ghidra")
        ghidra_addr = self._to_ghidra_addr(addr)

        block = self.basic_block_model.getFirstCodeBlockContaining(ghidra_addr, self.task_monitor)
        if block is None:
            raise ValueError(f"Cannot find block containing address {hex(addr)}")
        instrs = []
        ii = self.program.getListing().getInstructions(block, True)
        for i in ii:
            instrs.append(self._normalize_ghidra_addr(i.getAddress()))
        start = self._normalize_ghidra_addr(block.getMinAddress())
        size = block.getNumAddresses()
        return BasicBlock(
            start=start,
            size=size,
            instruction_addrs=tuple(instrs),
        )

    @override
    def get_instr_bytes_at(self, addr: int, num_instr=1):
        ghidra_addr = self._to_ghidra_addr(addr)
        instr = self.program.getListing().getInstructionContaining(ghidra_addr)
        if instr is None:
            return None
        b = bytes(instr.getBytes())
        for _i in range(1, num_instr):
            instr = instr.getNext()
            b = b"".join([b, bytes(instr.getBytes())])
        logger.info(
            f"got instr bytes of length {len(b)} for {num_instr} instrs at {hex(addr)} with ghidra"
        )
        return b

    @override
    def get_unused_funcs(self) -> list[FunctionInfo]:
        logger.info("getting unused funcs with ghidra")
        fi = self.program.getListing().getFunctions(True)
        unused_funcs: list[FunctionInfo] = []
        for f in fi:
            if not f.getSymbol().hasReferences():
                b = f.getBody()
                unused_funcs.append(
                    FunctionInfo(
                        addr=self._normalize_ghidra_addr(b.getMinAddress()),
                        size=b.getNumAddresses(),
                    )
                )
        return unused_funcs

    @override
    def iter_symbols(self) -> Iterator[Symbol]:
        logger.info("getting all symbols with ghidra")
        listing = self.program.getListing()
        memory = self.program.getMemory()
        si = self.program.getSymbolTable().getAllSymbols(True)
        for s in filter(lambda symbol: symbol.isPrimary(), cast("Iterable[Any]", si)):
            name = s.getName()
            sym_addr = s.getAddress()
            if sym_addr is None:
                continue

            # Imports are anchored either outside the memory address space
            # entirely or inside a synthetic block Ghidra appends past the end
            # of the image. Both are placeholders, not locations.
            block = memory.getBlock(sym_addr)
            if not sym_addr.isMemoryAddress() or (
                block is not None and block.getName() == self.EXTERNAL_BLOCK
            ):
                yield ExternalSymbol(name=name)
                continue

            # Ghidra labels some structures twice: once where the file holds
            # them and once where they are loaded. Only the latter falls in a
            # memory block, and only that one is a real address.
            if block is None:
                continue

            address: int = self._normalize_ghidra_addr(sym_addr)
            # Ghidra labels the file structures it parsed as well as the loaded
            # image. Those are at file offsets rather than addresses, so
            # normalizing puts them below the image base; they are not part of
            # what gets mapped and cannot be referenced.
            if address < 0:
                continue

            # getFunctionAt rather than the symbol's own type: it needs no extra
            # ghidra submodule import, and an entry point is exactly what takes
            # the instruction-set bit below.
            function = listing.getFunctionAt(sym_addr)
            if function is not None:
                if self.is_thumb(address):
                    address += 1
                yield MappedSymbol(
                    name=name,
                    addr=address,
                    is_stub=bool(function.isThunk()),
                )
            else:
                yield MappedSymbol(name=name, addr=address)

    @override
    def get_function(self, name_or_addr: int | str) -> FunctionInfo | None:
        if isinstance(name_or_addr, int):
            func = self.program.getListing().getFunctionContaining(
                self._to_ghidra_addr(name_or_addr)
            )
            if func is None:
                return None
        elif isinstance(name_or_addr, str):
            funcs = self.program.getListing().getGlobalFunctions(name_or_addr)
            if len(funcs) == 0:
                return None
            func = funcs[0]
        else:
            raise TypeError(f"Invalid type for name_or_addr: {type(name_or_addr)}")

        b = func.getBody()
        return FunctionInfo(
            addr=self._normalize_ghidra_addr(b.getMinAddress()),
            size=b.getNumAddresses(),
        )

    def thumb_mode(self, addr: int) -> bool | None:
        """Return the Ghidra ARM mode, or None when it is unknown."""
        register = self.program.getRegister("TMode")
        if register is None:
            return False

        value = self.program.getProgramContext().getRegisterValue(
            register, self._to_ghidra_addr(addr)
        )
        if value is None or not value.hasValue():
            logger.info(f"address {hex(addr)} has no TMode value in ghidra")
            return None

        is_thumb = value.unsignedValueIgnoreMask.intValue() == 1
        logger.info(f"address {hex(addr)} {'is' if is_thumb else 'is not'} thumb from ghidra")
        return is_thumb

    @override
    def is_thumb(self, addr: int) -> bool:
        mode = self.thumb_mode(addr)
        if mode is None:
            raise UnknownInstructionModeError(
                f"Cannot determine ARM instruction mode at {hex(addr)}"
            )
        return mode
