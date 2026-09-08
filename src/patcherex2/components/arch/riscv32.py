from patcherex2.components.arch import ArchitectureInfo

RISCV32 = ArchitectureInfo(
    elf_arch={
        "e_machine": "EM_RISCV",
        "ei_class": "ELFCLASS32",
        "ei_data": "ELFDATA2LSB",
    },
    nop_bytes=b"\x13\x00\x00\x00",
    nop_size=4,
    jmp_asm="tail {dst}",
    jmp_size=8,
    jmp_max_distance=0x7FFFF000,
    alignment=2,
    bits=32,
    is_variable_length_isa=True,
    instr_size=-1,
    call_asm="call {dst}",
    pc_reg_names=["pc", "ra"],
    save_context_asm="",
    restore_context_asm="",
)
