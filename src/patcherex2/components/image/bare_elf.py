from __future__ import annotations

from elftools.construct.lib.container import Container
from typing_extensions import override

from patcherex2.components.allocation_manager import AllocationManager
from patcherex2.components.binary_analyzer import BinaryAnalyzer
from patcherex2.components.image.elf import ElfImageBackend, elf_section_flags_from_memory_flags


class BareMetalElfImageBackend(ElfImageBackend):
    """ELF storage mechanics for an explicitly placed bare-metal image."""

    @override
    def _init_memory_analysis(self, allocation_manager: AllocationManager) -> None:
        """Allocation authority is supplied by the placement policy."""

    def next_file_offset(self) -> int:
        highest_file_offset = self.file_size
        for segment in self._segments:
            highest_file_offset = max(
                highest_file_offset,
                segment["p_offset"] + segment["p_filesz"],
            )
        return (highest_file_offset + 0xFFFF) & ~0xFFFF

    def occupied_load_ranges(self) -> list[range]:
        return [
            range(segment["p_paddr"], segment["p_paddr"] + segment["p_filesz"])
            for segment in self._segments
            if segment["p_type"] == "PT_LOAD" and segment["p_filesz"] > 0
        ]

    def occupied_runtime_ranges(self) -> list[range]:
        return [
            range(segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"])
            for segment in self._segments
            if segment["p_type"] == "PT_LOAD" and segment["p_memsz"] > 0
        ]

    @override
    def finalize(
        self, allocation_manager: AllocationManager, binary_analyzer: BinaryAnalyzer
    ) -> None:
        allocation_manager.finalize()
        if not allocation_manager.new_mapped_blocks:
            return
        max_align = self.page_alignment()
        self._append_new_segments(allocation_manager, max_align)
        self._segments = self._merge_adjacent_load_segments(self._segments)
        self._write_headers()

    def _append_new_segments(self, allocation_manager: AllocationManager, max_align: int) -> None:
        for block in allocation_manager.new_mapped_blocks:
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
                    sh_flags=elf_section_flags_from_memory_flags(block.flag),
                    sh_addr=block.mem_addr,
                    sh_offset=block.file_addr,
                    sh_size=block.size,
                    sh_link=0,
                    sh_info=0,
                    sh_addralign=max_align,
                    sh_entsize=0,
                )
            )
        self._segments.sort(key=lambda segment: segment["p_offset"])

    def _write_headers(self) -> None:
        # The relocated table is file metadata outside every authorized PT_LOAD
        # range, so retaining PT_PHDR would falsely describe it as memory-resident.
        self._segments = self._order_program_headers(
            [segment for segment in self._segments if segment["p_type"] != "PT_PHDR"]
        )
        program_header_offset = max(
            self.file_size,
            *(segment["p_offset"] + segment["p_filesz"] for segment in self._segments),
        )
        program_headers = b"".join(
            self._elf.structs.Elf_Phdr.build(segment) for segment in self._segments
        )
        self.update_binary_content(program_header_offset, program_headers)

        section_header_offset = program_header_offset + len(program_headers)
        section_headers = b"".join(
            self._elf.structs.Elf_Shdr.build(section) for section in self._sections
        )
        self.update_binary_content(section_header_offset, section_headers)

        elf_header = self._elf.header
        elf_header["e_phnum"] = len(self._segments)
        elf_header["e_phoff"] = program_header_offset
        elf_header["e_shnum"] = len(self._sections)
        elf_header["e_shoff"] = section_header_offset
        self.update_binary_content(0, self._elf.structs.Elf_Ehdr.build(elf_header))
