import logging
import re

from ..allocation_managers.allocation_manager import MemoryFlag

logger = logging.getLogger(__name__)


class Utils:
    def __init__(self, p, binary_path):
        self.p = p
        self.binary_path = binary_path

    def insert_trampoline_code(
        self, addr, instrs, force_insert=False, detour_pos=-1, symbols=None, base_reg=None
    ):
        logger.debug(f"Inserting trampoline code at {hex(addr)}: {instrs}")
        symbols = symbols if symbols else {}
        assert force_insert or self.is_valid_insert_point(
            addr
        ), f"Cannot insert instruction at {hex(addr)}"
        if not force_insert:
            moved_instrs = self.get_instrs_to_be_moved(addr)
            moved_instrs_len = len(
                self.p.assembler.assemble(
                    moved_instrs,
                    addr,  # TODO: we don't really need this addr, but better than 0x0 because 0x0 is too far away from the code
                    is_thumb=self.p.binary_analyzer.is_thumb(addr),
                )
            )
        else:
            moved_instrs = ""
            moved_instrs_len = 0

        load_addr_size = len(
            self.p.assembler.assemble(
                self.p.target.emit_load_addr(addr),
                addr,
                is_thumb=self.p.binary_analyzer.is_thumb(addr),
            )
        )
        # calculate the expected size of the trampoline
        # by summing the size of the compiled instructions
        # excluding the POINTER_HANDLER, the size of the
        # expanded POINTER_HANDLER pseudo-instruction
        trampoline_size = (
            len(
                self.p.assembler.assemble(
                    "\n".join(
                        [
                            line
                            for line in instrs.splitlines()
                            if "POINTER_HANDLER" not in line
                        ]
                    )
                    + "\n"
                    + moved_instrs
                    + "\n"
                    + self.p.target.JMP_ASM.format(dst=hex(addr + moved_instrs_len)),
                    addr,  # TODO: we don't really need this addr, but better than 0x0 because 0x0 is too far away from the code
                    symbols=symbols,
                    is_thumb=self.p.binary_analyzer.is_thumb(addr),
                )
            )
            + len(re.findall("POINTER_HANDLER", instrs)) * load_addr_size
        )
        is_thumb = self.p.binary_analyzer.is_thumb(addr)
        thunk_instrs_len = 0
        if base_reg:
            # emit thunk with addr instead of the trampoline address to calculate the size
            thunk_instrs_len = len(
                self.p.assembler.assemble(
                    self.p.target.emit_thunk(base_reg, addr, is_thumb),
                    addr,
                    is_thumb=is_thumb,
                )
            )
            trampoline_size += thunk_instrs_len
        if detour_pos == -1:
            trampoline_block = self.p.allocation_manager.allocate(
                trampoline_size, align=0x4, flag=MemoryFlag.RX
            )  # TODO: get alignment from arch info
            logger.debug(f"Allocated trampoline block: {trampoline_block}")
            mem_addr = trampoline_block.mem_addr
            file_addr = trampoline_block.file_addr
        else:
            mem_addr = detour_pos
            file_addr = self.p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
        self.p.sypy_info["patcherex_added_functions"].append(hex(mem_addr))

        if base_reg:
            instrs = self.p.target.emit_thunk(
                base_reg, mem_addr, is_thumb=is_thumb
            ) + instrs

        # replace addresses here
        instrs = self.rewrite_addresses(instrs, addr, mem_addr, is_thumb=is_thumb)

        trampoline_instrs_with_jump_back = (
            instrs
            + "\n"
            + moved_instrs
            + "\n"
            + self.p.target.JMP_ASM.format(dst=hex(addr + moved_instrs_len))
        )

        trampoline_bytes = self.p.assembler.assemble(
            trampoline_instrs_with_jump_back,
            mem_addr,
            symbols=symbols,
            is_thumb=self.p.binary_analyzer.is_thumb(addr),
        )
        self.p.binfmt_tool.update_binary_content(file_addr, trampoline_bytes)
        jmp_to_trampoline = self.p.assembler.assemble(
            self.p.target.JMP_ASM.format(dst=hex(mem_addr)),
            addr,
            is_thumb=self.p.binary_analyzer.is_thumb(addr),
        )
        self.p.binfmt_tool.update_binary_content(
            self.p.binary_analyzer.mem_addr_to_file_offset(addr), jmp_to_trampoline
        )

    def get_instrs_to_be_moved(self, addr, ignore_unmovable=False):
        basic_block = self.p.binary_analyzer.get_basic_block(addr)
        idx = basic_block["instruction_addrs"].index(addr)
        end = addr + self.p.target.JMP_SIZE
        instrs = b""

        for insn_addr in basic_block["instruction_addrs"][idx:] + [basic_block["end"]]:
            if end <= insn_addr:
                # we have enough space to insert a jump
                disasms = self.p.disassembler.disassemble(
                    instrs,
                    addr,
                    is_thumb=self.p.binary_analyzer.is_thumb(addr),
                )
                return "\n".join(
                    [self.p.disassembler.to_asm_string(d) for d in disasms]
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

    def is_valid_insert_point(self, addr):
        return self.get_instrs_to_be_moved(addr) is not None

    def is_movable_instruction(self, addr):
        is_thumb = self.p.binary_analyzer.is_thumb(addr)
        insn = self.p.binary_analyzer.get_instr_bytes_at(addr)
        asm = self.p.disassembler.disassemble(insn, addr, is_thumb=is_thumb)[0]
        asm = self.p.disassembler.to_asm_string(asm)
        for addr in [0x0, 0x7F00000, 0xFE000000]:
            if self.p.assembler.assemble(asm, addr, is_thumb=is_thumb) != insn:
                return False
        return True

    def rewrite_addresses(self, instrs, addr, mem_addr, is_thumb=False):
        pointer_pat = re.compile(
            r"POINTER_HANDLER (?P<register>[^, ]+), [^0-9]?(?P<imm>[0-9]+)"
        )

        # uses a fake address to get the approximate size of
        load_addr_insns_size = len(
            self.p.assembler.assemble(self.p.target.emit_load_addr(addr))
        )

        instrs_size = (
            len(
                self.p.assembler.assemble(
                    "\n".join(
                        [
                            line
                            for line in instrs.splitlines()
                            if "POINTER_HANDLER" not in line
                        ]
                    ), addr, is_thumb=self.p.binary_analyzer.is_thumb(addr)
                )
            )
            + len(pointer_pat.findall(instrs)) * load_addr_insns_size
        )

        # rewrite addresses
        new_instrs = []
        for line in instrs.splitlines():
            line = line.strip()
            new_line = line
            if match_result := pointer_pat.search(line):
                reg_name = match_result.group("register")
                goto_addr = int(match_result.group("imm"))
                # only rewrite goto addresses in between the start of the moved instructions
                # to the end of the moved instructions
                if goto_addr - addr >= 0 and goto_addr - addr <= self.p.target.JMP_SIZE:
                    # TODO: setting the thumb bit using is_thumb isn't always necessarily true
                    goto_addr = mem_addr + instrs_size + (goto_addr - addr) | int(is_thumb)
                new_line = self.p.target.emit_load_addr(goto_addr, reg_name=reg_name)
                logger.debug(f"POINTER_HANDLER -> {new_line}")
            new_instrs.append(new_line)
        instrs = "\n".join(new_instrs)
        logger.debug(f"Replace addresses: {instrs}")
        return instrs
