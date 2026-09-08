from __future__ import annotations

import logging
import sys
from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager
from typing import Protocol, final

from patcherex2.components.binary_analyzer import BasicBlock, BinaryAnalyzer, FunctionInfo

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


class IdaFunction(Protocol):
    @property
    def start_ea(self) -> int: ...

    @property
    def end_ea(self) -> int: ...

    @property
    def flags(self) -> int: ...

    def code_items(self) -> Iterable[int]: ...


class IdaBlock(Protocol):
    @property
    def start_ea(self) -> int: ...

    @property
    def end_ea(self) -> int: ...


class IdaSegment(Protocol):
    @property
    def type(self) -> int: ...

    @property
    def perm(self) -> int: ...


class IdaNameApi(Protocol):
    def get_nlist_size(self) -> int: ...

    def get_nlist_name(self, idx: int, /) -> str | None: ...

    def get_nlist_ea(self, idx: int, /) -> int: ...

    def get_name_ea(self, _from: int, name: str, /) -> int: ...


class IdaNaltApi(Protocol):
    def get_imagebase(self) -> int: ...


class IdaIdaApi(Protocol):
    def inf_is_dll(self) -> bool: ...


class IdaLoaderApi(Protocol):
    def get_file_type_name(self) -> str | None: ...

    def get_fileregion_offset(self, ea: int, /) -> int: ...


class IdaFuncsApi(Protocol):
    @property
    def FUNC_THUNK(self) -> int: ...  # noqa: N802 - IDA publishes this name.

    def get_func(self, ea: int, /) -> IdaFunction | None: ...

    def get_func_qty(self) -> int: ...

    def getn_func(self, n: int, /) -> IdaFunction | None: ...


class IdaUtilsApi(Protocol):
    def XrefsTo(  # noqa: N802 - IDA publishes this API name.
        self, ea: int, flags: int, /
    ) -> Iterable[object]: ...


class IdaGdlApi(Protocol):
    @property
    def FC_PREDS(self) -> int: ...  # noqa: N802 - IDA publishes this name.

    def FlowChart(  # noqa: N802 - IDA publishes this API name.
        self, *, f: IdaFunction, flags: int
    ) -> Iterable[IdaBlock]: ...


class IdaBytesApi(Protocol):
    def get_item_size(self, ea: int, /) -> int: ...

    def get_bytes(self, ea: int, size: int, /) -> bytes: ...


class IdaIdpApi(Protocol):
    def str2reg(self, p: str, /) -> int: ...


class IdaSegregsApi(Protocol):
    def get_sreg(self, ea: int, rg: int, /) -> int: ...


class IdaSegmentApi(Protocol):
    @property
    def SEG_XTRN(self) -> int: ...  # noqa: N802 - IDA publishes this name.

    def getseg(self, ea: int, /) -> IdaSegment | None: ...


class IdaIdaapiApi(Protocol):
    @property
    def BADADDR(self) -> int: ...  # noqa: N802 - IDA publishes this name.


@final
class IDAAnalyzer(BinaryAnalyzer):
    _DEFAULT_LOAD_BASE = 0x0

    def __init__(
        self,
        *,
        ida_name: IdaNameApi,
        ida_nalt: IdaNaltApi,
        ida_ida: IdaIdaApi,
        ida_loader: IdaLoaderApi,
        ida_funcs: IdaFuncsApi,
        idautils: IdaUtilsApi,
        ida_gdl: IdaGdlApi,
        ida_bytes: IdaBytesApi,
        ida_idp: IdaIdpApi,
        ida_segregs: IdaSegregsApi,
        ida_segment: IdaSegmentApi,
        ida_idaapi: IdaIdaapiApi,
    ) -> None:
        self.ida_name: IdaNameApi = ida_name
        self.ida_nalt: IdaNaltApi = ida_nalt
        self.ida_ida: IdaIdaApi = ida_ida
        self.ida_loader: IdaLoaderApi = ida_loader
        self.ida_funcs: IdaFuncsApi = ida_funcs
        self.idautils: IdaUtilsApi = idautils
        self.ida_gdl: IdaGdlApi = ida_gdl
        self.ida_bytes: IdaBytesApi = ida_bytes
        self.ida_idp: IdaIdpApi = ida_idp
        self.ida_segregs: IdaSegregsApi = ida_segregs
        self.ida_segment: IdaSegmentApi = ida_segment
        self.ida_idaapi: IdaIdaapiApi = ida_idaapi
        self._load_base: int | None = None

    @classmethod
    @contextmanager
    def load_binary(
        cls,
        binary_path: str,
        processor: str | None = None,
    ) -> Generator[IDAAnalyzer, None, None]:
        """Open a binary with IDAlib and close its database after analysis."""
        # IDAlib requires idapro to be imported before any IDAPython module.
        import idapro  # type: ignore[unresolved-import]  # Optional IDA runtime.

        arguments = None if processor is None else f"-p{processor}"
        status = idapro.open_database(binary_path, True, arguments)
        if status != 0:
            raise RuntimeError(f"IDA failed to open and analyze {binary_path!r} (status {status})")

        try:
            import ida_bytes  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_funcs  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_gdl  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_ida  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_idaapi  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_idp  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_loader  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_nalt  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_name  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_segment  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import ida_segregs  # type: ignore[unresolved-import]  # Provided by IDAlib.
            import idautils  # type: ignore[unresolved-import]  # Provided by IDAlib.

            yield cls(
                ida_name=ida_name,
                ida_nalt=ida_nalt,
                ida_ida=ida_ida,
                ida_loader=ida_loader,
                ida_funcs=ida_funcs,
                idautils=idautils,
                ida_gdl=ida_gdl,
                ida_bytes=ida_bytes,
                ida_idp=ida_idp,
                ida_segregs=ida_segregs,
                ida_segment=ida_segment,
                ida_idaapi=ida_idaapi,
            )
        finally:
            idapro.close_database()

    @property
    @override
    def load_base(self) -> int:
        if self._load_base is None:
            self._load_base = self.ida_nalt.get_imagebase()
        return self._load_base

    @override
    def normalize_addr(self, addr: int) -> int:
        if self.ida_ida.inf_is_dll():
            return addr - self.load_base
        return addr

    @override
    def denormalize_addr(self, addr: int) -> int:
        if self.ida_ida.inf_is_dll():
            return addr + self.load_base
        return addr

    @override
    def mem_addr_to_file_offset(self, addr: int) -> int:
        file_type = self.ida_loader.get_file_type_name()
        if file_type is not None and "intel hex" in file_type.lower():
            return addr
        ida_addr = self.denormalize_addr(addr)
        file_offset = self.ida_loader.get_fileregion_offset(ida_addr)
        if file_offset == -1:
            raise ValueError(f"Memory address {hex(addr)} is not mapped to the file")
        return file_offset

    @override
    def get_basic_block(self, addr: int) -> BasicBlock:
        addr = self.denormalize_addr(addr)
        func = self.ida_funcs.get_func(addr)
        if func is None:
            raise ValueError(f"address {addr:#x} is not inside an IDA-recognized function")
        instr_addrs = list(func.code_items())
        assert addr in instr_addrs, "Invalid address"
        flowchart = self.ida_gdl.FlowChart(f=func, flags=self.ida_gdl.FC_PREDS)

        for block in flowchart:
            if block.start_ea <= addr < block.end_ea:
                return BasicBlock(
                    start=self.normalize_addr(block.start_ea),
                    size=block.end_ea - block.start_ea,
                    instruction_addrs=tuple(
                        self.normalize_addr(ea)
                        for ea in instr_addrs
                        if block.start_ea <= ea < block.end_ea
                    ),
                )
        raise ValueError(f"Cannot find a block containing address {addr:#x}")

    @override
    def get_instr_bytes_at(self, addr: int, num_instr: int = 1):
        addr = self.denormalize_addr(addr)
        total_bytes = b""
        current_addr = addr
        for _ in range(num_instr):
            instr_len = self.ida_bytes.get_item_size(current_addr)
            total_bytes += self.ida_bytes.get_bytes(current_addr, instr_len)
            current_addr += instr_len
        return total_bytes

    @override
    def get_unused_funcs(self) -> list[FunctionInfo]:
        logger.info("Getting unused functions with IDA")
        unused_funcs: list[FunctionInfo] = []
        for index in range(self.ida_funcs.get_func_qty()):
            func = self.ida_funcs.getn_func(index)
            if func is None or func.end_ea <= func.start_ea:
                continue
            for _ in self.idautils.XrefsTo(func.start_ea, 0):
                break
            else:
                unused_funcs.append(
                    FunctionInfo(
                        addr=self.normalize_addr(func.start_ea),
                        size=func.end_ea - func.start_ea,
                    )
                )
        return unused_funcs

    @override
    def iter_symbols(self) -> Iterator[Symbol]:
        logger.info("Getting all symbols with IDA")
        for symbol in range(self.ida_name.get_nlist_size()):
            name = self.ida_name.get_nlist_name(symbol)
            if not name:
                continue
            addr = self.ida_name.get_nlist_ea(symbol)
            if addr == self.ida_idaapi.BADADDR:
                continue

            # Imports live in a segment the analyzer synthesises to anchor names
            # whose definitions come from elsewhere; those addresses are
            # placeholders rather than locations.
            segment = self.ida_segment.getseg(addr)
            if segment is not None and segment.type == self.ida_segment.SEG_XTRN:
                yield ExternalSymbol(name=name)
                continue

            address: int = self.normalize_addr(addr)
            func = self.ida_funcs.get_func(addr)
            if func is not None and func.start_ea == addr:
                # Only an entry point takes the instruction-set bit; setting it
                # on data would hand out an address one byte past the datum.
                if self.is_thumb(address):
                    address += 1
                is_stub = bool(func.flags & self.ida_funcs.FUNC_THUNK)
                yield MappedSymbol(name=name, addr=address, is_stub=is_stub)
            else:
                yield MappedSymbol(name=name, addr=address)

    @override
    def get_function(self, name_or_addr: int | str) -> FunctionInfo | None:
        if isinstance(name_or_addr, str):
            addr = self.ida_name.get_name_ea(self.ida_idaapi.BADADDR, name_or_addr)
            if addr == self.ida_idaapi.BADADDR:
                return None
        else:
            addr = self.denormalize_addr(name_or_addr)
        func = self.ida_funcs.get_func(addr)
        if func is None:
            return None
        return FunctionInfo(
            addr=self.normalize_addr(func.start_ea),
            size=func.end_ea - func.start_ea,
        )

    @override
    def is_thumb(self, addr: int) -> bool:
        addr = self.denormalize_addr(addr)
        return self.ida_segregs.get_sreg(addr, self.ida_idp.str2reg("T")) == 1
