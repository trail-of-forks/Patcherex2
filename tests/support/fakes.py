from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from types import ModuleType
from typing import Any

from patcherex2.components.allocation_manager import Allocator, Block, MappedBlock, MemoryFlag
from patcherex2.components.assembler import Assembler
from patcherex2.components.binary_analyzer import BasicBlock, FunctionInfo
from patcherex2.components.binary_analyzer.ida import IDAAnalyzer, IdaBlock, IdaFunction
from patcherex2.components.binary_analyzer.symbol import MappedSymbol, Symbol
from patcherex2.components.disassemblers.disassembler import Disassembler, Instruction
from patcherex2.components.image import ImageBackend
from patcherex2.components.symbol_resolver import SymbolResolver


class FakeBinaryAnalyzer:
    """Configurable analyzer that satisfies the complete analyzer protocol."""

    def __init__(
        self,
        *,
        load_base: int = 0,
        symbols: Mapping[str, MappedSymbol] | None = None,
        map_address: Callable[[int], int] | None = None,
        get_block: Callable[[int], BasicBlock] | None = None,
        get_instructions: Callable[[int, int], bytes | None] | None = None,
        get_function: Callable[[int | str], FunctionInfo | None] | None = None,
        is_thumb: Callable[[int], bool] | None = None,
    ) -> None:
        self._load_base = load_base
        self._symbols = {} if symbols is None else dict(symbols)
        self._map_address = map_address or (lambda address: address)
        self._get_block = get_block
        self._get_instructions = get_instructions
        self._get_function = get_function
        self._is_thumb = is_thumb or (lambda _address: False)

    @property
    def load_base(self) -> int:
        return self._load_base

    def normalize_addr(self, addr: int) -> int:
        return addr

    def denormalize_addr(self, addr: int) -> int:
        return addr

    def mem_addr_to_file_offset(self, addr: int) -> int:
        return self._map_address(addr)

    def get_basic_block(self, addr: int) -> BasicBlock:
        if self._get_block is None:
            raise AssertionError("get_basic_block was not configured")
        return self._get_block(addr)

    def get_instr_bytes_at(self, addr: int, num_instr: int = 1) -> bytes | None:
        if self._get_instructions is None:
            raise AssertionError("get_instr_bytes_at was not configured")
        return self._get_instructions(addr, num_instr)

    def get_unused_funcs(self) -> list[FunctionInfo]:
        return []

    def iter_symbols(self) -> Iterator[Symbol]:
        yield from self._symbols.values()

    def get_all_symbols(self) -> dict[str, MappedSymbol]:
        return dict(self._symbols)

    def get_function(self, name_or_addr: int | str) -> FunctionInfo | None:
        if self._get_function is None:
            return None
        return self._get_function(name_or_addr)

    def is_thumb(self, addr: int) -> bool:
        return self._is_thumb(addr)


class FakeCompiler:
    """Compiler protocol implementation backed by a test callback."""

    preserve_none = False

    def __init__(self, compile_code: Callable[..., bytes] | None = None) -> None:
        self._compile_code = compile_code or (lambda *_args, **_kwargs: b"")

    def compile(
        self,
        code: str,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        is_thumb: bool = False,
        **kwargs: Any,
    ) -> bytes:
        return self._compile_code(
            code,
            base=base,
            symbols=symbols,
            extension=extension,
            extra_compiler_flags=extra_compiler_flags,
            is_thumb=is_thumb,
            **kwargs,
        )


class CallbackAssemblyBackend:
    """Assembly backend protocol implementation backed by a test callback."""

    def __init__(self, assemble: Callable[..., bytes]) -> None:
        self._assemble = assemble

    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        return self._assemble(code, base=base, is_thumb=is_thumb)


def make_assembler(
    assemble: Callable[..., bytes],
    analyzer: FakeBinaryAnalyzer | None = None,
) -> Assembler:
    """Build the real symbol-resolving assembler around a callback backend."""
    analyzer = analyzer or FakeBinaryAnalyzer()
    return Assembler(SymbolResolver(analyzer), CallbackAssemblyBackend(assemble))


class FakeDisassembler(Disassembler):
    """Disassembler backed by a test callback."""

    def __init__(self, disassemble: Callable[..., list[Instruction]] | None = None) -> None:
        self._disassemble = disassemble or (lambda *_args, **_kwargs: [])

    def disassemble(self, input: bytes, base: int = 0, **kwargs: Any) -> list[Instruction]:
        return self._disassemble(input, base=base, **kwargs)


class FakeImageBackend(ImageBackend):
    """In-memory image backend for component tests."""

    def __init__(
        self,
        *,
        file_size: int = 0,
        position_independent: bool = False,
        alignment: int = 0x1000,
        minimum_address: Callable[[int], int | None] | None = None,
    ) -> None:
        super().__init__("", file_size=file_size)
        self._position_independent = position_independent
        self._alignment = alignment
        self._minimum_address = minimum_address

    @property
    def is_position_independent(self) -> bool:
        return self._position_independent

    def finalize(self, allocation_manager, binary_analyzer) -> None:
        del allocation_manager, binary_analyzer

    def save_binary(self, filename: str | None = None) -> None:
        del filename

    def get_binary_content(self, offset: int, size: int) -> bytes:
        size = self._read_size(offset, size)
        return self._overlay_file_updates(offset, b"\x00" * size)

    def page_alignment(self) -> int:
        return self._alignment

    def minimum_memory_address_for_new_segment(self, file_offset: int) -> int | None:
        if self._minimum_address is None:
            return None
        return self._minimum_address(file_offset)

    @property
    def updates(self) -> list[tuple[int, bytes]]:
        return [(update["offset"], update["content"]) for update in self.file_updates]


class FakeAllocator:
    """Allocator protocol implementation that records every request."""

    def __init__(
        self,
        allocation_factory: Callable[[int, Mapping[str, object]], MappedBlock] | None = None,
    ) -> None:
        self.new_mapped_blocks: list[MappedBlock] = []
        self.requests: list[tuple[int, dict[str, object]]] = []
        self.freed: list[Block] = []
        self._allocation_factory = allocation_factory

    def allocate(
        self,
        size: int,
        *,
        flag: MemoryFlag = MemoryFlag.RWX,
        align: int = 1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> MappedBlock:
        options: dict[str, object] = {
            "flag": flag,
            "align": align,
            "near_addr": near_addr,
            "max_dist": max_dist,
            "address_validator": address_validator,
        }
        self.requests.append((size, options))
        if self._allocation_factory is not None:
            return self._allocation_factory(size, options)
        return MappedBlock(file_addr=0, addr=0x5000, size=size, is_free=False, flag=flag)

    def free(self, block: Block) -> None:
        block.is_free = True
        self.freed.append(block)


class FakeLoadModelContext:
    """Focused structural fake for load models that only consume an allocator."""

    def __init__(self, allocation_manager: Allocator) -> None:
        self.allocation_manager = allocation_manager


class FakeIdaFunction:
    def __init__(
        self,
        *,
        start: int = 0,
        end: int = 0,
        flags: int = 0,
        instruction_addresses: Iterable[int] = (),
    ) -> None:
        self.start_ea = start
        self.end_ea = end
        self.flags = flags
        self._instruction_addresses = tuple(instruction_addresses)

    def code_items(self) -> Iterable[int]:
        return self._instruction_addresses


class FakeIdaBlock:
    def __init__(self, start: int, end: int) -> None:
        self.start_ea = start
        self.end_ea = end


class FakeIdaSegment:
    def __init__(self, segment_type: int, permissions: int = 0) -> None:
        self.type = segment_type
        self.perm = permissions


class FakeIdaApi(ModuleType):
    """Composite test double satisfying every IDA module protocol we consume."""

    BADADDR = -1
    FUNC_THUNK = 0x80
    FC_PREDS = 1
    SEG_XTRN = 1

    def __init__(
        self,
        *,
        entries: Iterable[tuple[str, int]] = (),
        functions: Mapping[int, FakeIdaFunction] | None = None,
        function_for: Callable[[int], FakeIdaFunction | None] | None = None,
        indexed_functions: Iterable[FakeIdaFunction | None] = (),
        segment_for: Callable[[int], FakeIdaSegment | None] | None = None,
        blocks_for: Callable[[IdaFunction], Iterable[IdaBlock]] | None = None,
        xrefs_to: Callable[[int], Iterable[object]] | None = None,
        image_base: int = 0,
        is_dll: bool = False,
        file_type: str = "ELF",
        file_offset: Callable[[int], int] | None = None,
        item_size: Callable[[int], int] | None = None,
        item_bytes: Callable[[int, int], bytes] | None = None,
        register_number: int = 0,
        segment_register: Callable[[int, int], int] | None = None,
    ) -> None:
        super().__init__("fake_ida_api")
        self.entries = tuple(entries)
        self.functions = {} if functions is None else dict(functions)
        self._function_for = function_for
        self.indexed_functions = tuple(indexed_functions)
        self._segment_for = segment_for or (lambda _address: None)
        self._blocks_for = blocks_for or (lambda _function: ())
        self._xrefs_to = xrefs_to or (lambda _address: ())
        self._image_base = image_base
        self._is_dll = is_dll
        self._file_type = file_type
        self._file_offset = file_offset or (lambda address: address)
        self._item_size = item_size or (lambda _address: 1)
        self._item_bytes = item_bytes or (lambda _address, size: b"\x00" * size)
        self._register_number = register_number
        self._segment_register = segment_register or (lambda _address, _register: 0)

    def get_nlist_size(self) -> int:
        return len(self.entries)

    def get_nlist_name(self, index: int) -> str | None:
        return self.entries[index][0]

    def get_nlist_ea(self, index: int) -> int:
        return self.entries[index][1]

    def get_name_ea(self, bad_address: int, name: str) -> int:
        return next((address for entry, address in self.entries if entry == name), bad_address)

    def get_imagebase(self) -> int:
        return self._image_base

    def inf_is_dll(self) -> bool:
        return self._is_dll

    def get_file_type_name(self) -> str:
        return self._file_type

    def get_fileregion_offset(self, address: int) -> int:
        return self._file_offset(address)

    def get_func(self, address: int) -> FakeIdaFunction | None:
        if self._function_for is not None:
            return self._function_for(address)
        return self.functions.get(address)

    def get_func_qty(self) -> int:
        return len(self.indexed_functions)

    def getn_func(self, index: int) -> FakeIdaFunction | None:
        return self.indexed_functions[index]

    def XrefsTo(  # noqa: N802 - matches the injected IDA API.
        self, address: int, flags: int
    ) -> Iterable[object]:
        del flags
        return self._xrefs_to(address)

    def FlowChart(  # noqa: N802 - matches the injected IDA API.
        self, *, f: IdaFunction, flags: int
    ) -> Iterable[IdaBlock]:
        del flags
        return self._blocks_for(f)

    def get_item_size(self, address: int) -> int:
        return self._item_size(address)

    def get_bytes(self, address: int, size: int) -> bytes:
        return self._item_bytes(address, size)

    def str2reg(self, name: str) -> int:
        del name
        return self._register_number

    def get_sreg(self, address: int, register: int) -> int:
        return self._segment_register(address, register)

    def getseg(self, address: int) -> FakeIdaSegment | None:
        return self._segment_for(address)


def make_ida_analyzer(api: FakeIdaApi) -> IDAAnalyzer:
    """Inject a protocol-complete fake into every IDA API role."""
    return IDAAnalyzer(
        ida_name=api,
        ida_nalt=api,
        ida_ida=api,
        ida_loader=api,
        ida_funcs=api,
        idautils=api,
        ida_gdl=api,
        ida_bytes=api,
        ida_idp=api,
        ida_segregs=api,
        ida_segment=api,
        ida_idaapi=api,
    )
