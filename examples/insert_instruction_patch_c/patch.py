import logging

from patcherex2 import (
    ComponentSelections,
    InsertInstructionPatch,
    InstructionPatchLanguage,
    PatchSession,
    TargetConfig,
)
from patcherex2.targets import ELF_AMD64_LINUX

logger = logging.getLogger("patcherex2.patch.instruction")
logger.setLevel(logging.INFO)

c_forward_header = """
// This string will be inserted outside the micropatch function. It will be
// inserted before your code.
// This is how you can define types and function forward declarations used by your C micropatch
#include <stdio.h>
"""

# The asm_header is inserted in the main body of the patch before the C code. It is useful for
# accessing the stack pointer, which is otherwise unavailable in our C code. This example moves
# rsp to r12, which is accessible.
# This means that inside the C code we can access the original stack pointer through r12.
# There is also an asm_footer
asm_header = "mov r12, rsp"

# We can access assembly registers directly by using their name, while still using high-level C
# constructs and intermediate variables. A return statement anywhere in the C micropatch jumps
# back to the next instruction after the micropatch insertion point.
c_str = """
rdi += rdi;
rdi += 5;
// Print out rsp as it was before the patch was started
printf("%p\\n", (void *) r12);
"""

# It is generally a good idea to mark some registers as scratch to give the compiler
# breathing room for allocating registers to use for intermediate variables in your micropatch
# All of the registers that we mark as scratch can be freely clobbered by the compiler
# Note that you can still read from scratch registers stored in the variables. What the scratch
# register denotation will indicate however is that the register can be re-used after the variable
# is no longer live.
c_scratch_regs = [
    "r8",
    "r9",
    "r10",
    "r11",
    "r13",
    "r14",
    "r15",
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
]

# By default floating point registers will have the 'float' type. We can use c_regs_sort to override
# certain registers so they hold different types. Here xmm8 is a double.
c_regs_sort = [("xmm8", "double")]

config = InsertInstructionPatch.CConfig(
    c_forward_header=c_forward_header,
    scratch_regs=c_scratch_regs,
    regs_sort=c_regs_sort,
    asm_header=asm_header,
)

with PatchSession.load_binary(
    "add",
    target=ELF_AMD64_LINUX,
    config=TargetConfig(selections=ComponentSelections(compiler="clang19")),
) as session:
    session.patches.append(
        InsertInstructionPatch(
            0x114D,
            c_str,
            language=InstructionPatchLanguage.C,
            c_config=config,
        )
    )
    session.apply_patches()
    session.save_binary()
