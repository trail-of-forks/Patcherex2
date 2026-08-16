from __future__ import annotations

import logging
import re

from ..allocation_managers.allocation_manager import MemoryFlag

logger = logging.getLogger(__name__)


class Utils:
    def __init__(self, p, binary_path: str) -> None:
        self.p = p
        self.binary_path = binary_path

    def _build_trampoline_bytes(
        self,
        addr: int,
        mem_addr: int,
        instrs: str,
        trampoline_instrs_with_jump_back: str,
        symbols: dict[str, int],
        language: str,
        asm_header: str,
    ) -> bytes:
        is_thumb = self.p.binary_analyzer.is_thumb(addr)
        if language != "C":
            return self.p.assembler.assemble(
                trampoline_instrs_with_jump_back,
                mem_addr,
                symbols=symbols,
                is_thumb=is_thumb,
            )

        compiled_asm_header = self.p.assembler.assemble(
            asm_header,
            mem_addr,
            symbols=symbols,
            is_thumb=is_thumb,
        )
        compiled_length = 0
        for _ in range(16):
            symbols_copy = dict(symbols)
            symbols_copy["_CALLBACK"] = (
                mem_addr + len(compiled_asm_header) + compiled_length
            )
            compiled_code = self.p.compiler.compile(
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
                "The compiled trampoline length did not converge at "
                f"memory address {hex(mem_addr)}"
            )

        trampoline_tail = self.p.assembler.assemble(
            trampoline_instrs_with_jump_back,
            mem_addr + len(compiled_asm_header) + len(compiled_code),
            symbols=symbols,
            is_thumb=is_thumb,
        )
        return compiled_asm_header + compiled_code + trampoline_tail

    def _allocate_trampoline(
        self,
        addr: int,
        initial_size: int,
        build,
    ):
        near_addr = addr if self.p.binfmt_tool.is_position_independent else None
        requested_size = initial_size
        for _ in range(16):
            block = self.p.allocation_manager.allocate(
                requested_size,
                align=self.p.archinfo.alignment,
                flag=MemoryFlag.RX,
                near_addr=near_addr,
            )
            trampoline_bytes = build(block.mem_addr)
            if len(trampoline_bytes) <= block.size:
                return block, trampoline_bytes
            self.p.allocation_manager.free(block)
            requested_size = len(trampoline_bytes)
        raise RuntimeError(
            f"Trampoline allocation did not converge for insertion at {hex(addr)}"
        )

    def insert_trampoline_code(
        self,
        addr: int,
        instrs: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        language="ASM",
        asm_header="",
        asm_footer="",
    ) -> None:
        logger.debug(f"Inserting trampoline code at {hex(addr)}: {instrs}")
        symbols = symbols if symbols else {}
        assert force_insert or self.is_valid_insert_point(addr), (
            f"Cannot insert instruction at {hex(addr)}"
        )
        if not force_insert:
            moved_instrs, moved_instrs_len = self.get_instrs_to_be_moved(addr)
        else:
            moved_instrs = ""
            _, moved_instrs_len = self.get_instrs_to_be_moved(
                addr,
                ignore_unmovable=True,
            )
        trampoline_instrs_with_jump_back = (
            (asm_footer if language == "C" else instrs)
            + "\n"
            + moved_instrs
            + "\n"
            + self.p.archinfo.jmp_asm.format(dst=hex(addr + moved_instrs_len))
        )

        def build(mem_addr):
            return self._build_trampoline_bytes(
                addr,
                mem_addr,
                instrs,
                trampoline_instrs_with_jump_back,
                symbols,
                language,
                asm_header,
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
            for block in self.p.allocation_manager.new_mapped_blocks:
                if block.mem_addr == mem_addr:
                    if len(trampoline_bytes) > block.size:
                        raise ValueError(
                            f"Trampoline at {hex(mem_addr)} needs "
                            f"{len(trampoline_bytes)} bytes, but its mapped block "
                            f"has only {block.size} bytes"
                        )
                    file_addr = block.file_addr
                    break
            else:
                file_addr = self.p.binary_analyzer.mem_addr_to_file_offset(mem_addr)

        self.p.sypy_info["patcherex_added_functions"].append(hex(mem_addr))
        self.p.binfmt_tool.update_binary_content(file_addr, trampoline_bytes)
        jmp_to_trampoline = self.p.assembler.assemble(
            self.p.archinfo.jmp_asm.format(dst=hex(mem_addr)),
            addr,
            is_thumb=self.p.binary_analyzer.is_thumb(addr),
        )
        self.p.binfmt_tool.update_binary_content(
            self.p.binary_analyzer.mem_addr_to_file_offset(addr), jmp_to_trampoline
        )

    def get_instrs_to_be_moved(
        self, addr: int, ignore_unmovable=False
    ) -> tuple[str, int] | None:
        basic_block = self.p.binary_analyzer.get_basic_block(addr)
        idx = basic_block["instruction_addrs"].index(addr)
        end = addr + self.p.archinfo.jmp_size
        instrs = b""

        for insn_addr in basic_block["instruction_addrs"][idx:] + [basic_block["end"]]:
            if end <= insn_addr:
                # we have enough space to insert a jump
                disasms = self.p.disassembler.disassemble(
                    instrs,
                    addr,
                    is_thumb=self.p.binary_analyzer.is_thumb(addr),
                )
                return (
                    "\n".join([self.p.disassembler.to_asm_string(d) for d in disasms]),
                    insn_addr - addr,
                )
            if insn_addr == basic_block["end"]:
                # we reached the end of the basic block
                return None
            if not ignore_unmovable and not self.is_movable_instruction(insn_addr):
                logger.error(f"Instruction at {hex(insn_addr)} is not movable")
                # we cannot insert a jump here
                return None
            instrs += self.p.binary_analyzer.get_instr_bytes_at(insn_addr)
        return None

    def is_valid_insert_point(self, addr: int) -> bool:
        return self.get_instrs_to_be_moved(addr) is not None

    def is_movable_instruction(self, addr: int) -> bool:
        is_thumb = self.p.binary_analyzer.is_thumb(addr)
        insn_bytes = self.p.binary_analyzer.get_instr_bytes_at(addr)
        disassembled = self.p.disassembler.disassemble(
            insn_bytes, addr, is_thumb=is_thumb
        )[0]
        # if instruction use PC as a base register, it's not movable
        tokens = re.split(r"\s|,|\[|\]", disassembled["op_str"])
        tokens = list(filter(None, tokens))
        if list(set(self.p.archinfo.pc_reg_names) & set(tokens)):
            return False
        # TODO: this assumes that keystone always gives abs addr when disassembling, but it might not be true
        disassembled = self.p.disassembler.to_asm_string(disassembled)
        for test_addr in [addr - 0x10000, addr + 0x10000]:
            re_assembled = self.p.assembler.assemble(
                disassembled, test_addr, is_thumb=is_thumb
            )
            re_disassembled = self.p.disassembler.disassemble(
                re_assembled, test_addr, is_thumb=is_thumb
            )[0]
            re_disassembled = self.p.disassembler.to_asm_string(re_disassembled)
            if re_disassembled != disassembled:
                return False
        return True
