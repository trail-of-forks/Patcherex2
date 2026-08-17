from .base import ArchInfo


class X86Info(ArchInfo):
    elf_arch = {
        "e_machine": "EM_386",
        "ei_class": "ELFCLASS32",
        "ei_data": "ELFDATA2LSB",
    }
    nop_bytes = b"\x90"
    nop_size = 1
    jmp_asm = "jmp {dst}"
    jmp_size = 5
    alignment = 4
    bits = 32
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "call {dst}"
    pc_reg_names = ["eip"]
    save_context_asm = """
    pusha
    """
    restore_context_asm = """
    popa
    """
