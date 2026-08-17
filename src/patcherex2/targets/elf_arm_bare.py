from collections.abc import Callable

from elftools.construct.lib import Container

from ..components.allocation_managers.allocation_manager import (
    AllocationManager,
    FileBlock,
    MemoryBlock,
    MemoryFlag,
)
from ..components.binfmt_tools.elf import ELF
from ..patches import InsertInstructionPatch
from .elf_arm_linux import ElfArmLinux


class FlashBlock(MemoryBlock):
    pass


class RamBlock(MemoryBlock):
    pass


class CustomAllocationManager(AllocationManager):
    def _create_new_mapped_block(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> bool:
        file_block = next(
            (block for block in self.blocks[FileBlock] if block.size == -1),
            None,
        )
        if file_block is None:
            return False

        file_addr = file_block.addr
        page_align = self.p.binfmt_tool.page_alignment()
        flash_block = next(
            (block for block in self.blocks[FlashBlock] if block.size == -1),
            None,
        )
        if flash_block is None:
            return False
        load_mem_addr = flash_block.addr + (file_addr - flash_block.addr) % page_align

        if flag == MemoryFlag.RW:
            ram_block = next(
                (block for block in self.blocks[RamBlock] if block.size == -1),
                None,
            )
            if ram_block is None:
                return False
            mem_addr = ram_block.addr + (file_addr - ram_block.addr) % page_align
        elif flag == MemoryFlag.RX:
            mem_addr = load_mem_addr
        else:
            raise NotImplementedError("Unknown MemoryFlag")

        max_block_size = self.p.binfmt_tool.flash_end - load_mem_addr
        if flag == MemoryFlag.RW:
            max_block_size = min(
                max_block_size,
                self.p.binfmt_tool.ram_end - mem_addr,
            )
        if max_block_size <= 0:
            return False

        block_size = self._prospective_open_end_size(
            mem_addr,
            size,
            align,
            near_addr,
            max_dist,
            address_validator,
            max_block_size,
        )
        if block_size is None:
            return False

        file_block.addr = file_addr + block_size
        flash_block.addr = load_mem_addr + block_size
        if flag == MemoryFlag.RW:
            ram_block.addr = mem_addr + block_size
        self._add_new_mapped_block(
            file_addr,
            mem_addr,
            block_size,
            flag,
            load_mem_addr=load_mem_addr,
        )
        return True


class CustomElf(ELF):
    def __init__(self, p, binary_path, **kwargs):
        assert (
            "flash_start" in kwargs
            and "flash_end" in kwargs
            and "ram_start" in kwargs
            and "ram_end" in kwargs
            and "insert_points" in kwargs
        )
        self.flash_start = kwargs["flash_start"]
        self.flash_end = kwargs["flash_end"]
        self.ram_start = kwargs["ram_start"]
        self.ram_end = kwargs["ram_end"]
        self.insert_points = kwargs["insert_points"]
        assert isinstance(self.insert_points, list)

        super().__init__(p, binary_path)

    def _init_memory_analysis(self):
        highest_flash_addr = self.flash_start
        highest_ram_addr = self.ram_start
        highest_file_offset = 0
        for segment in self._segments:
            seg_start = segment["p_vaddr"]
            seg_end = segment["p_vaddr"] + segment["p_memsz"]
            if (
                self.flash_start <= seg_start < self.flash_end
                and self.flash_start <= seg_end < self.flash_end
                and seg_end > highest_flash_addr
            ):
                highest_flash_addr = seg_end
            if (
                self.ram_start <= seg_start < self.ram_end
                and self.ram_start <= seg_end < self.ram_end
                and seg_end > highest_ram_addr
            ):
                highest_ram_addr = seg_end

            highest_file_offset = max(
                highest_file_offset, segment["p_offset"] + segment["p_filesz"]
            )

        highest_file_offset = (highest_file_offset + 0xFFFF) & ~0xFFFF
        block = FileBlock(highest_file_offset, -1)
        self.p.allocation_manager.add_block(block)
        block = RamBlock(highest_ram_addr, -1)
        self.p.allocation_manager.add_block(block)
        block = FlashBlock(highest_flash_addr, -1)
        self.p.allocation_manager.add_block(block)

    def finalize(self):
        self.p.allocation_manager.finalize()
        if len(self.p.allocation_manager.new_mapped_blocks) == 0:
            return

        max_align = max([segment["p_align"] for segment in self._segments] + [0])

        copy_to_ram = ""
        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            if block.mem_addr != block.load_mem_addr:
                copy_to_ram += f"""
ldr r0, ={hex(block.load_mem_addr)}
ldr r1, ={hex(block.mem_addr)}
ldr r2, ={hex(block.size)}
copy:
ldrb r3, [r0], #1
strb r3, [r1], #1
subs r2, r2, #1
bne copy
"""
        for insert_point in self.insert_points:
            InsertInstructionPatch(insert_point, copy_to_ram, save_context=True).apply(
                self.p
            )
        self.p.allocation_manager.finalize()
        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            self._segments.append(
                Container(
                    p_type="PT_LOAD",
                    p_offset=block.file_addr,
                    p_filesz=block.size,
                    p_vaddr=block.mem_addr,
                    p_paddr=block.load_mem_addr,
                    p_memsz=block.size,
                    p_flags=block.flag,
                    p_align=max_align,
                )
            )

            self._sections.append(
                Container(
                    sh_name=0,
                    sh_type="SHT_PROGBITS",
                    sh_flags=2,
                    sh_addr=block.mem_addr,
                    sh_offset=block.file_addr,
                    sh_size=block.size,
                    sh_link=0,
                    sh_info=0,
                    sh_addralign=max_align,
                    sh_entsize=0,
                )
            )

        # sort segments by p_offset
        self._segments = sorted(self._segments, key=lambda x: x["p_offset"])

        # try to merge load segments if they are adjacent and have the same flags and same alignment
        # new size = sum of sizes of the two segments + gap between them
        while True:
            new_segments = []
            i = 0
            while i < len(self._segments) - 1:
                prev_seg = self._segments[i]
                next_seg = self._segments[i + 1]
                if (
                    prev_seg["p_type"] == next_seg["p_type"] == "PT_LOAD"
                    and prev_seg["p_offset"] + prev_seg["p_filesz"]
                    == next_seg["p_offset"]
                    and prev_seg["p_vaddr"] + prev_seg["p_memsz"] == next_seg["p_vaddr"]
                    and prev_seg["p_flags"] == next_seg["p_flags"]
                    and prev_seg["p_align"] == next_seg["p_align"]
                ):
                    new_segments.append(
                        Container(
                            p_type="PT_LOAD",
                            p_offset=prev_seg["p_offset"],
                            p_filesz=prev_seg["p_filesz"]
                            + next_seg["p_filesz"]
                            + (
                                next_seg["p_offset"]
                                - (prev_seg["p_offset"] + prev_seg["p_filesz"])
                            ),
                            p_vaddr=prev_seg["p_vaddr"],
                            p_paddr=prev_seg["p_paddr"],
                            p_memsz=prev_seg["p_memsz"]
                            + next_seg["p_memsz"]
                            + (
                                next_seg["p_vaddr"]
                                - (prev_seg["p_vaddr"] + prev_seg["p_memsz"])
                            ),
                            p_flags=prev_seg["p_flags"],
                            p_align=prev_seg["p_align"],
                        )
                    )
                    i += 2
                else:
                    new_segments.append(prev_seg)
                    i += 1
            if i == len(self._segments) - 1:
                new_segments.append(self._segments[i])
            if new_segments == self._segments:
                break
            self._segments = new_segments

        # generate new phdr at end of the file and update ehdr
        last_seg = max(self._segments, key=lambda x: x["p_offset"])
        phdr_start = last_seg["p_offset"] + last_seg["p_filesz"]
        new_phdr = b""
        for segment in self._segments:
            new_phdr += self._elf.structs.Elf_Phdr.build(segment)
        self.p.binfmt_tool.update_binary_content(phdr_start, new_phdr)

        ehdr = self._elf.header
        ehdr["e_phnum"] = len(self._segments)
        ehdr["e_phoff"] = phdr_start

        # generate new shdr at end of the file and update ehdr
        shdr_start = phdr_start + len(new_phdr)
        new_shdr = b""
        for section in self._sections:
            new_shdr += self._elf.structs.Elf_Shdr.build(section)
        self.p.binfmt_tool.update_binary_content(shdr_start, new_shdr)

        ehdr["e_shnum"] = len(self._sections)
        ehdr["e_shoff"] = shdr_start
        new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
        self.p.binfmt_tool.update_binary_content(0, new_ehdr)


class ElfArmBare(ElfArmLinux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_binfmt_tool(self, binfmt_tool, **kwargs):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return CustomElf(self.p, self.binary_path, **kwargs)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return CustomAllocationManager(self.p)
        raise NotImplementedError()
