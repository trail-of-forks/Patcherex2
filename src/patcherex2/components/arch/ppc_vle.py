from patcherex2.components.arch import ArchitectureInfo

PPC_VLE = ArchitectureInfo(
    elf_arch={
        "e_machine": "EM_PPC",
        "ei_class": "ELFCLASS32",
        "ei_data": "ELFDATA2MSB",
    },
    nop_bytes=b"\x01\x00\x00\x00",
    nop_size=4,
    jmp_asm="b {dst}",
    jmp_size=4,
    jmp_max_distance=0x01FFFFFC,
    alignment=4,
    bits=32,
    is_variable_length_isa=True,
    instr_size=-1,
    call_asm="bl {dst}",
    pc_reg_names=[],
    save_context_asm="",
    restore_context_asm="",
)
