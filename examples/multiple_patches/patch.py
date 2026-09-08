from patcherex2 import InsertDataPatch, InsertInstructionPatch, PatchSession
from patcherex2.targets import ELF_AMD64_LINUX

asm_string = """
    cmp edx, [rbp-0xc]
    jl less
    SAVE_CONTEXT
    lea rdi, [<my_str>]
    call <puts>
    RESTORE_CONTEXT
    mov rsi, [rbp-0x18]
    mov byte ptr [rsi+rax], 0
    mov eax, edx
    leave
    ret
less:
"""

with PatchSession.load_binary("getline", target=ELF_AMD64_LINUX) as session:
    session.patches.append(InsertInstructionPatch(0x120B, "mov esi, 0xa\n"))
    session.patches.append(InsertDataPatch("my_str", b"Ran out of space\0"))
    session.patches.append(InsertInstructionPatch(0x1199, "mov [rbp-0xc],esi"))
    session.patches.append(InsertInstructionPatch(0x11C1, asm_string))
    session.apply_patches()
    session.save_binary()
