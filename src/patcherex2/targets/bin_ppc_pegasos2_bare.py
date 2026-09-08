"""
0000000000000000-000000001fffffff (prio 0, ram): pegasos2.ram
00000000fff00000-00000000fff7ffff (prio 0, rom): pegasos2.rom
execution starts at 0xfff00100 (0x100 from ROM base).
first 0x100 bytes are the interrupt vector table
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any

import capstone

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import Assembler
from patcherex2.components.assembler.keystone import KeystoneAssemblyBackend, keystone
from patcherex2.components.disassemblers.capstone import Capstone
from patcherex2.components.image import ImageBackend
from patcherex2.targets.profiles import PPC_LINUX
from patcherex2.targets.target import ComponentFactory, ImageProfile, TargetDefinition

from ..components.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from ..components.binary_analyzer.angr import AngrAnalyzer
from ..components.compilers import Compiler
from ..components.compilers.clang import ClangObjectCompiler
from ..components.compilers.elf import create_elf_compiler
from ..components.image.raw import RawImageBackend

logger = logging.getLogger(__name__)

_DEFAULT_LOAD_BASE = 0xFFF00000
_DEFAULT_ENTRY = 0xFFF00100
_DEFAULT_MAX_SIZE = 0x80000
_CLANG_VERSION = 15


class Pegasos2RawImageBackend(RawImageBackend):
    """Raw image backend constrained to the Pegasos2 ROM region."""

    def __init__(
        self,
        binary_path: str,
        load_base: int = _DEFAULT_LOAD_BASE,
        max_size: int = _DEFAULT_MAX_SIZE,
    ) -> None:
        super().__init__(binary_path)
        self.load_base = load_base
        self.max_size = max_size
        if self.file_size > max_size:
            raise ValueError(
                f"Input binary ({self.file_size} bytes) is larger than "
                f"the configured ROM region ({hex(max_size)})"
            )

    @override
    def initialize_allocation_manager(self, allocation_manager) -> None:
        allocation_manager.add_block(
            MappedBlock(
                file_addr=0,
                addr=self.load_base,
                size=self.file_size,
                is_free=False,
                flag=MemoryFlag.RX,
            )
        )
        allocation_manager.add_block(FileBlock(addr=self.file_size, size=-1))
        allocation_manager.add_block(MemoryBlock(addr=self.load_base + self.file_size, size=-1))

    @override
    def page_alignment(self) -> int:
        return 4

    @override
    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        end = offset + len(new_content)
        if end > self.max_size:
            raise ValueError(
                f"Patched binary would grow to {hex(end)} bytes, exceeding "
                f"the configured ROM size of {hex(self.max_size)}"
            )
        super().update_binary_content(offset, new_content)

    @override
    def append_to_binary_content(self, new_content: bytes) -> None:
        end = self.file_size + len(new_content)
        if end > self.max_size:
            raise ValueError(
                f"Appending {len(new_content)} bytes would grow the binary "
                f"to {hex(end)}, exceeding the configured ROM size of "
                f"{hex(self.max_size)}"
            )
        super().append_to_binary_content(new_content)


def _keystone_assembler(symbol_resolver: Any) -> Assembler:
    backend = KeystoneAssemblyBackend(
        keystone.KS_ARCH_PPC,
        keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_PPC32,
    )
    return Assembler(symbol_resolver, backend)


def _nyxstone_assembler(symbol_resolver: Any) -> Assembler:
    from patcherex2.components.assembler.nyxstone import NyxstoneAssemblyBackend

    backend = NyxstoneAssemblyBackend("powerpc-unknown-linux-gnu", "7450", "+altivec")
    return Assembler(symbol_resolver, backend)


def _capstone_disassembler() -> Any:
    disassembler = Capstone(
        capstone.CS_ARCH_PPC,
        capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_32,
    )
    disassembler.cs.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME
    return disassembler


def _nyxstone_disassembler() -> Any:
    from patcherex2.components.disassemblers.nyxstone import Nyxstone

    return Nyxstone("powerpc-unknown-linux-gnu", "7450", "+altivec")


def _compiler(
    *,
    architecture: Any,
    image: Any,
    symbol_resolver: Any,
    assembler: Any,
    disassembler: Any,
) -> Compiler:
    del assembler, disassembler
    object_compiler = ClangObjectCompiler(
        _CLANG_VERSION,
        [
            "-target",
            "powerpc-unknown-elf",
            "-mcpu=7450",
            "-mbig-endian",
            "-ffreestanding",
            "-nostdlib",
            "-fno-pic",
            "-fno-builtin",
        ],
        image.is_position_independent,
        architecture.non_pic_compiler_flags,
    )
    return create_elf_compiler(
        architecture=architecture,
        symbol_resolver=symbol_resolver,
        object_compiler=object_compiler,
        linker=object_compiler.linker,
        position_independent=image.is_position_independent,
    )


PEGASOS2_ARCHITECTURE = PPC_LINUX.model_copy(
    update={
        "name": "ppc-pegasos2",
        "assembler": ComponentFactory(
            role="assembler",
            default="keystone",
            choices={
                "keystone": _keystone_assembler,
                "nyxstone": _nyxstone_assembler,
            },
        ),
        "compiler": ComponentFactory(
            role="compiler",
            default="clang",
            choices={"clang": _compiler},
        ),
        "disassembler": ComponentFactory(
            role="disassembler",
            default="capstone",
            choices={
                "capstone": _capstone_disassembler,
                "nyxstone": _nyxstone_disassembler,
            },
        ),
    }
)


def _backend(
    binary_path: str, *, config: Mapping[str, Any] | None = None
) -> Pegasos2RawImageBackend:
    return Pegasos2RawImageBackend(binary_path, **dict(config or {}))


def _analyzer(
    binary_path: str,
    _image: ImageBackend,
    *,
    config: Mapping[str, Any] | None = None,
) -> AbstractContextManager[AngrAnalyzer]:
    analyzer_config = dict(config or {})
    base_addr = analyzer_config.pop("base_addr", _DEFAULT_LOAD_BASE)
    entry_point = analyzer_config.pop("entry_point", _DEFAULT_ENTRY)
    if analyzer_config:
        names = ", ".join(sorted(analyzer_config))
        raise ValueError(f"Pegasos2 analyzer does not accept options: {names}")
    return AngrAnalyzer.load_binary(
        binary_path,
        angr_kwargs={
            "main_opts": {
                "backend": "blob",
                "arch": "PowerPC:BE:32:default",
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
            "auto_load_libs": False,
        },
        angr_cfg_kwargs={"normalize": True, "data_references": True},
    )


PEGASOS2_RAW_IMAGE = ImageProfile(
    name="pegasos2-raw",
    backend=ComponentFactory(role="image backend", default="raw", choices={"raw": _backend}),
    allocator=ComponentFactory(
        role="allocation manager",
        default="default",
        choices={
            "default": lambda analyzer, backend, config=None: AllocationManager(
                binary_analyzer=analyzer,
                image=backend,
                **dict(config or {}),
            )
        },
    ),
)

PPC_PEGASOS2_RAW_BARE = TargetDefinition(
    name="ppc-pegasos2-raw-bare",
    architecture=PEGASOS2_ARCHITECTURE,
    image=PEGASOS2_RAW_IMAGE,
    analyzer=ComponentFactory(role="binary analyzer", default="angr", choices={"angr": _analyzer}),
)
