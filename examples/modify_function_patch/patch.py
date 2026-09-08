from patcherex2 import ModifyFunctionPatch, PatchSession
from patcherex2.targets import ELF_AMD64_LINUX

new_add_func = """
int add(int a, int b) {
    return a * b;
}
"""

with PatchSession.load_binary("add", target=ELF_AMD64_LINUX) as session:
    session.patches.append(ModifyFunctionPatch("add", new_add_func))
    session.apply_patches()
    session.save_binary("add_patched")
