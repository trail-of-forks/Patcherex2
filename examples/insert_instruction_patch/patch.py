from patcherex2 import InsertInstructionPatch, PatchSession
from patcherex2.targets import ELF_AMD64_LINUX

asm_str = """
    add edi, edi
    add edi, 5
"""

with PatchSession.load_binary("add", target=ELF_AMD64_LINUX) as session:
    session.patches.append(InsertInstructionPatch(0x114D, asm_str))
    session.apply_patches()
    session.save_binary()
