from __future__ import annotations

import logging
import re
from collections.abc import Callable
from functools import partial
from typing import Annotated, final

from pydantic import Field

from patcherex2.components.allocation_manager import (
    Allocator,
    MappedBlock,
    MemoryFlag,
)
from patcherex2.components.arch import ArchitectureInfo
from patcherex2.components.assembler import Assembler
from patcherex2.components.binary_analyzer import BasicBlock, BinaryAnalyzer
from patcherex2.components.compilers import Compiler
from patcherex2.components.disassemblers.disassembler import Disassembler
from patcherex2.components.image import ImageBackend
from patcherex2.models import FrozenPatcherexModel

logger = logging.getLogger(__name__)


@final
class JumpAllocationOptions(FrozenPatcherexModel):
    """Address constraints for allocating code reached by a direct jump."""

    near_addr: Annotated[int, Field(ge=0)]
    max_dist: Annotated[int, Field(ge=0)] | None
    address_validator: Callable[[int], bool] | None


class InvalidInsertPointError(ValueError):
    """Raised when a trampoline detour cannot start at the requested address."""

    def __init__(self, addr: int, candidates: list[int]) -> None:
        self.addr = addr
        self.candidates = tuple(candidates)
        message = f"Cannot insert instruction at {hex(addr)}"
        if candidates:
            candidate_text = ", ".join(hex(candidate) for candidate in candidates)
            message += f"; mechanically valid points in the same basic block: {candidate_text}"
        super().__init__(message)


class Utils:
    def __init__(
        self,
        architecture: ArchitectureInfo,
        assembler: Assembler,
        disassembler: Disassembler,
        compiler: Compiler,
        binary_analyzer: BinaryAnalyzer,
        allocation_manager: Allocator,
        image: ImageBackend,
        added_functions: list[str] | None = None,
    ) -> None:
        self.architecture: ArchitectureInfo = architecture
        self.assembler: Assembler = assembler
        self.disassembler: Disassembler = disassembler
        self.compiler: Compiler = compiler
        self.binary_analyzer: BinaryAnalyzer = binary_analyzer
        self.allocation_manager: Allocator = allocation_manager
        self.image: ImageBackend = image
        self.added_functions: list[str] = [] if added_functions is None else added_functions

    def _available_jump_distance(self, reserved_size: int = 0) -> int | None:
        if reserved_size < 0:
            raise ValueError("Reserved jump size cannot be negative")
        max_jump_distance = self.architecture.jmp_max_distance
        if max_jump_distance is None:
            return None
        if reserved_size > max_jump_distance:
            raise ValueError(
                f"Reserved jump size {hex(reserved_size)} exceeds architecture "
                f"maximum distance {hex(max_jump_distance)}"
            )
        return max_jump_distance - reserved_size

    def jump_allocation_options(
        self,
        near_addr: int,
        reserved_size: int = 0,
    ) -> JumpAllocationOptions:
        """Build allocation constraints for a jump originating at ``near_addr``."""
        return JumpAllocationOptions(
            near_addr=near_addr,
            max_dist=self._available_jump_distance(reserved_size),
            address_validator=partial(self.architecture.is_jump_reachable, near_addr),
        )

    def validate_jump_reachability(
        self, source_addr: int, target_addr: int, reserved_size: int = 0
    ) -> None:
        max_dist = self._available_jump_distance(reserved_size)
        if max_dist is not None and abs(target_addr - source_addr) > max_dist:
            raise ValueError(
                f"Jump from {hex(source_addr)} to {hex(target_addr)} exceeds "
                f"architecture maximum distance {hex(max_dist)}"
            )
        if not self.architecture.is_jump_reachable(source_addr, target_addr):
            raise ValueError(
                f"Jump from {hex(source_addr)} to {hex(target_addr)} is not reachable on this architecture"
            )

    def _validate_relocated_instructions(
        self,
        relocated: bytes,
        mem_addr: int,
        moved_instrs: str,
        is_thumb: bool,
    ) -> None:
        if not moved_instrs:
            return
        actual = tuple(
            self.disassembler.to_asm_string(disasm).strip()
            for disasm in self.disassembler.disassemble(
                relocated,
                mem_addr,
                is_thumb=is_thumb,
            )
        )
        expected = tuple(line.strip() for line in moved_instrs.splitlines() if line.strip())
        if any(
            actual[index : index + len(expected)] == expected
            for index in range(len(actual) - len(expected) + 1)
        ):
            return
        raise ValueError(
            f"Relocating instructions to {hex(mem_addr)} changes their "
            f"semantics: expected sequence {expected!r}, got {actual!r}"
        )

    def _build_trampoline_bytes(
        self,
        addr: int,
        mem_addr: int,
        instrs: str,
        moved_instrs: str,
        jump_back_instr: str,
        jump_back_target: int,
        symbols: dict[str, int],
        is_c: bool,
        asm_header: str,
        asm_footer: str,
    ) -> bytes:
        is_thumb = self.binary_analyzer.is_thumb(addr)
        if not is_c:
            patch_bytes = b""
            tail_source = f"{instrs}\n{moved_instrs}\n{jump_back_instr}"
        else:
            compiled_asm_header = self.assembler.assemble(
                asm_header,
                mem_addr,
                symbols=symbols,
                is_thumb=is_thumb,
            )
            compiled_length = 0
            for _ in range(16):
                symbols_copy = dict(symbols)
                symbols_copy["_CALLBACK"] = mem_addr + len(compiled_asm_header) + compiled_length
                compiled_code = self.compiler.compile(
                    instrs,
                    base=mem_addr + len(compiled_asm_header),
                    symbols=symbols_copy,
                    is_thumb=is_thumb,
                    extra_compiler_flags=["-Os"],
                )
                if len(compiled_code) == compiled_length:
                    break
                compiled_length = len(compiled_code)
            else:
                raise RuntimeError(
                    f"The compiled trampoline length did not converge at memory address {hex(mem_addr)}"
                )
            patch_bytes = compiled_asm_header + compiled_code
            tail_source = f"{asm_footer}\n{moved_instrs}\n{jump_back_instr}"

        tail_addr = mem_addr + len(patch_bytes)
        tail_bytes = self.assembler.assemble(
            tail_source,
            tail_addr,
            symbols=symbols,
            is_thumb=is_thumb,
        )
        jump_back_addr = tail_addr + max(
            0,
            len(tail_bytes) - self.architecture.jmp_size,
        )
        self.validate_jump_reachability(jump_back_addr, jump_back_target)
        self._validate_relocated_instructions(
            tail_bytes,
            tail_addr,
            moved_instrs,
            is_thumb,
        )
        return patch_bytes + tail_bytes

    def allocate_generated_code(
        self,
        initial_size: int,
        build: Callable[[int], bytes],
        *,
        align: int,
        flag: MemoryFlag,
        allocation_options: Callable[[int], JumpAllocationOptions] | None = None,
    ) -> tuple[MappedBlock, bytes]:
        requested_size = initial_size
        for _ in range(16):
            options = allocation_options(requested_size) if allocation_options is not None else None
            block = self.allocation_manager.allocate(
                requested_size,
                align=align,
                flag=flag,
                near_addr=None if options is None else options.near_addr,
                max_dist=None if options is None else options.max_dist,
                address_validator=None if options is None else options.address_validator,
            )
            generated = build(block.mem_addr)
            if len(generated) <= block.size:
                return block, generated
            self.allocation_manager.free(block)
            requested_size = len(generated)
        raise RuntimeError("Generated-code allocation did not converge")

    def _allocate_trampoline(
        self,
        addr: int,
        initial_size: int,
        build: Callable[[int], bytes],
    ) -> tuple[MappedBlock, bytes]:
        requested_size = initial_size
        for _ in range(16):
            options = self.jump_allocation_options(addr, requested_size)
            block = self.allocation_manager.allocate(
                requested_size,
                align=self.architecture.alignment,
                flag=MemoryFlag.RX,
                near_addr=options.near_addr,
                max_dist=options.max_dist,
                address_validator=options.address_validator,
            )
            trampoline_bytes = build(block.mem_addr)
            if len(trampoline_bytes) <= block.size:
                return block, trampoline_bytes
            self.allocation_manager.free(block)
            requested_size = len(trampoline_bytes)
        raise RuntimeError(f"Trampoline allocation did not converge for insertion at {hex(addr)}")

    def insert_trampoline_code(
        self,
        addr: int,
        instrs: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        is_c=False,
        asm_header="",
        asm_footer="",
    ) -> None:
        logger.debug(f"Inserting trampoline code at {hex(addr)}: {instrs}")
        symbols = symbols if symbols else {}
        basic_block = self.binary_analyzer.get_basic_block(addr)
        analysis = self.get_instrs_to_be_moved(
            addr,
            ignore_unmovable=force_insert,
            basic_block=basic_block,
        )
        if analysis is None:
            raise InvalidInsertPointError(
                addr,
                self.find_valid_insert_points_near(
                    addr,
                    basic_block=basic_block,
                ),
            )
        moved_instrs, moved_instrs_len = analysis
        if force_insert:
            moved_instrs = ""
        jump_back_target = addr + moved_instrs_len
        jump_back_instr = self.architecture.jmp_asm.format(dst=hex(jump_back_target))

        def build(mem_addr):
            return self._build_trampoline_bytes(
                addr,
                mem_addr,
                instrs,
                moved_instrs,
                jump_back_instr,
                jump_back_target,
                symbols,
                is_c,
                asm_header,
                asm_footer,
            )

        if detour_pos == -1:
            initial_bytes = build(addr)
            trampoline_block, trampoline_bytes = self._allocate_trampoline(
                addr,
                len(initial_bytes),
                build,
            )
            logger.debug(f"Allocated trampoline block: {trampoline_block}")
            mem_addr = trampoline_block.mem_addr
            file_addr = trampoline_block.file_addr
        else:
            mem_addr = detour_pos
            trampoline_bytes = build(mem_addr)
            self.validate_jump_reachability(addr, mem_addr, len(trampoline_bytes))
            for block in self.allocation_manager.new_mapped_blocks:
                if block.mem_addr <= mem_addr < block.mem_addr + block.size:
                    offset = mem_addr - block.mem_addr
                    if len(trampoline_bytes) > block.size - offset:
                        raise ValueError(
                            f"Trampoline at {hex(mem_addr)} needs "
                            f"{len(trampoline_bytes)} bytes, but its mapped block "
                            f"has only {block.size - offset} bytes"
                        )
                    file_addr = block.file_addr + offset
                    break
            else:
                file_addr = self.binary_analyzer.mem_addr_to_file_offset(mem_addr)

        self.added_functions.append(hex(mem_addr))
        self.image.update_binary_content(file_addr, trampoline_bytes)
        jmp_to_trampoline = self.assembler.assemble(
            self.architecture.jmp_asm.format(dst=hex(mem_addr)),
            addr,
            is_thumb=self.binary_analyzer.is_thumb(addr),
        )
        self.image.update_binary_content(
            self.binary_analyzer.mem_addr_to_file_offset(addr), jmp_to_trampoline
        )

    def _get_instrs_to_be_moved_from_block(
        self,
        addr: int,
        basic_block: BasicBlock,
        ignore_unmovable: bool = False,
    ) -> tuple[str, int] | None:
        idx = basic_block.instruction_addrs.index(addr)
        end = addr + self.architecture.jmp_size
        instrs = b""

        for insn_addr in basic_block.instruction_addrs[idx:] + (basic_block.end,):
            if end <= insn_addr:
                # we have enough space to insert a jump
                disasms = self.disassembler.disassemble(
                    instrs,
                    addr,
                    is_thumb=self.binary_analyzer.is_thumb(addr),
                )
                return (
                    "\n".join([self.disassembler.to_asm_string(d) for d in disasms]),
                    insn_addr - addr,
                )
            if insn_addr == basic_block.end:
                # we reached the end of the basic block
                return None
            if not ignore_unmovable and not self.is_movable_instruction(insn_addr):
                logger.error(f"Instruction at {hex(insn_addr)} is not movable")
                # we cannot insert a jump here
                return None
            instr_bytes = self.binary_analyzer.get_instr_bytes_at(insn_addr)
            if instr_bytes is None:
                return None
            instrs += instr_bytes
        return None

    def get_instrs_to_be_moved(
        self,
        addr: int,
        ignore_unmovable: bool = False,
        basic_block: BasicBlock | None = None,
    ) -> tuple[str, int] | None:
        if basic_block is None:
            basic_block = self.binary_analyzer.get_basic_block(addr)
        return self._get_instrs_to_be_moved_from_block(
            addr,
            basic_block,
            ignore_unmovable,
        )

    def is_valid_insert_point(self, addr: int) -> bool:
        return self.get_instrs_to_be_moved(addr) is not None

    def find_valid_insert_points_near(
        self,
        addr: int,
        limit: int = 4,
        basic_block: BasicBlock | None = None,
    ) -> list[int]:
        if basic_block is None:
            basic_block = self.binary_analyzer.get_basic_block(addr)
        candidates = [
            candidate
            for candidate in basic_block.instruction_addrs
            if candidate != addr
            and self._get_instrs_to_be_moved_from_block(candidate, basic_block) is not None
        ]
        candidates.sort(key=lambda candidate: (abs(candidate - addr), candidate))
        return candidates[:limit]

    def is_movable_instruction(self, addr: int) -> bool:
        is_thumb = self.binary_analyzer.is_thumb(addr)
        insn_bytes = self.binary_analyzer.get_instr_bytes_at(addr)
        if insn_bytes is None:
            return False
        disassembled = self.disassembler.disassemble(insn_bytes, addr, is_thumb=is_thumb)[0]
        # if instruction use PC as a base register, it's not movable
        tokens = re.split(r"\s|,|\[|\]", disassembled["op_str"])
        tokens = list(filter(None, tokens))
        if list(set(self.architecture.pc_reg_names) & set(tokens)):
            return False
        # TODO: this assumes that keystone always gives abs addr when disassembling, but it might not be true
        disassembled = self.disassembler.to_asm_string(disassembled)
        for test_addr in [addr - 0x10000, addr + 0x10000]:
            re_assembled = self.assembler.assemble(disassembled, test_addr, is_thumb=is_thumb)
            re_disassembled = self.disassembler.disassemble(
                re_assembled, test_addr, is_thumb=is_thumb
            )[0]
            re_disassembled = self.disassembler.to_asm_string(re_disassembled)
            if re_disassembled != disassembled:
                return False
        return True
