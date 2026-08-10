from __future__ import annotations

import logging
import sys
import tempfile
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, cast, final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from .binary_analyzer import BinaryAnalyzer
from .symbol import ExternalSymbol, MappedSymbol, Symbol

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingModuleSource]
        Address,
    )


@final
class GhidraAnalyzer(BinaryAnalyzer):
    #: Synthetic block the analyzer appends past the end of the image to
    #: anchor names whose definitions live elsewhere.
    EXTERNAL_BLOCK = "EXTERNAL"

    def __init__(self, binary_path: str, **kwargs):
        import pyghidra

        self.temp_proj_dir_ctx = tempfile.TemporaryDirectory()
        self.temp_proj_dir = self.temp_proj_dir_ctx.__enter__()

        # Forwarded to pyghidra.open_program: `language` and `compiler` let a
        # target override Ghidra's auto-detection, which picks the wrong
        # processor variant for some binaries.
        self.pyghidra_ctx = pyghidra.open_program(
            binary_path, self.temp_proj_dir, **kwargs
        )
        self.flatapi = self.pyghidra_ctx.__enter__()
        self.currentProgram = self.flatapi.getCurrentProgram()

        import ghidra.program.model.block  # pyright: ignore[reportMissingModuleSource]

        self.bbm = ghidra.program.model.block.BasicBlockModel(self.currentProgram)

    def shutdown(self):
        self.pyghidra_ctx.__exit__(None, None, None)
        self.temp_proj_dir_ctx.__exit__(None, None, None)

    @property
    @override
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

    def _normalize_ghidra_addr(self, addr: Address) -> int:
        """Normalize a Ghidra ``Address`` to a plain normalized int."""
        return self.normalize_addr(addr.getOffset())

    def _to_ghidra_addr(self, addr: int) -> Address:
        """Denormalize a normalized int into a Ghidra ``Address``."""
        return self.flatapi.toAddr(hex(self.denormalize_addr(addr)))

    @override
    def mem_addr_to_file_offset(self, addr: int) -> int:
        ghidra_addr = self._to_ghidra_addr(addr)
        try:
            return (
                self.currentProgram.getMemory()
                .getAddressSourceInfo(ghidra_addr)
                .getFileOffset()
            )
        except Exception:  # noqa: BLE001
            raise ValueError("Can't get file offset for addr") from None

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
            "end": self._normalize_ghidra_addr(block.getMinAddress())
            + block.getNumAddresses(),
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
            f"got instr bytes of length {len(b)} for {num_instr} instrs at {hex(addr)} with ghidra"
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
    def iter_symbols(self) -> Iterator[Symbol]:
        from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingModuleSource]
            Symbol as GhidraSymbol,
        )

        logger.info("getting all symbols with ghidra")
        listing = self.currentProgram.getListing()
        memory = self.currentProgram.getMemory()
        si = self.currentProgram.getSymbolTable().getAllSymbols(True)
        for s in filter(lambda s: s.isPrimary(), cast(Iterable[GhidraSymbol], si)):
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
                yield ExternalSymbol(name)
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
                yield MappedSymbol(name, address, is_stub=bool(function.isThunk()))
            else:
                yield MappedSymbol(name, address)

    @override
    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        if isinstance(name_or_addr, int):
            func = self.currentProgram.getListing().getFunctionContaining(
                self._to_ghidra_addr(name_or_addr)
            )
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
        """
        Whether ``addr`` is Thumb, or None when it genuinely cannot be determined.

        Unlike :meth:`is_thumb` this does not fall back to a guess, so a caller
        that is able to refuse an address can tell "definitely ARM" apart from
        "no idea".

        Ghidra tracks the instruction set in the ``TMode`` register context,
        which it populates during disassembly. Where it has a value, that value
        is an authoritative statement about the address; where it has none, the
        address was never disassembled and no answer is available.

        :param addr: The address to query, in the same (normalized) convention
            the other methods here take.
        :return: True for Thumb, False for ARM, None if undeterminable.
        """
        r = self.currentProgram.getRegister("TMode")
        if r is None:
            # No TMode register at all means a non-ARM architecture, where
            # "not Thumb" is a definite answer rather than a missing one.
            return False
        v = self.currentProgram.getProgramContext().getRegisterValue(
            r, self._to_ghidra_addr(addr)
        )
        if v is None or not v.hasValue():
            logger.info(f"address {hex(addr)} has no TMode value in ghidra")
            return None
        t = v.unsignedValueIgnoreMask.intValue() == 1
        logger.info(f"address {hex(addr)} {'is' if t else 'is not'} thumb from ghidra")
        return t

    @override
    def is_thumb(self, addr: int) -> bool:
        """
        Whether ``addr`` is Thumb, defaulting to ARM when undeterminable.

        Prefer :meth:`thumb_mode` where an undeterminable address can be
        refused: decoding Thumb bytes as ARM fuses two 16-bit instructions into
        one, so a wrong answer here silently relocates instructions that do not
        exist in the binary.
        """
        mode = self.thumb_mode(addr)
        if mode is None:
            logger.warning(
                f"Cannot determine whether {hex(addr)} is ARM or Thumb: ghidra "
                f"has no TMode value for it. Assuming ARM, which will decode "
                f"incorrectly if it is in fact Thumb. Use thumb_mode() to "
                f"detect this case."
            )
            return False
        return mode
