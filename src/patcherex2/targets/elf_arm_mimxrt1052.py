"""MIMXRT1052 target using caller-authorized bare-metal placement."""

from patcherex2.targets.elf_arm_bare import ARM_ELF_BARE

# Board capacity is not authorization to overwrite its unused-looking contents.
# Callers supply flash/RAM ranges and initialization points just as for ARM_ELF_BARE.
ARM_MIMXRT1052_ELF = ARM_ELF_BARE.model_copy(update={"name": "arm-mimxrt1052-elf"})
