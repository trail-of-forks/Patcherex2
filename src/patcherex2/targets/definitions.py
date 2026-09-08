from patcherex2.targets.profiles import (
    AARCH64_LINUX,
    AMD64_LINUX,
    AMD64_LINUX_RECOMP,
    ARM_LINUX,
    ARM_LINUX_RECOMP,
    ELF_IMAGE,
    MIPS64_LINUX,
    MIPS64EL_LINUX,
    MIPS_LINUX,
    MIPSEL_LINUX,
    PPC64_LINUX,
    PPC64LE_LINUX,
    PPC_LINUX,
    S390X_LINUX,
    X86_LINUX,
    standard_analyzer_factory,
)
from patcherex2.targets.target import ArchitectureProfile, TargetDefinition

STANDARD_ANALYZERS = standard_analyzer_factory()


def _linux_elf_target(name: str, architecture: ArchitectureProfile) -> TargetDefinition:
    return TargetDefinition(
        name=name,
        architecture=architecture,
        image=ELF_IMAGE,
        analyzer=STANDARD_ANALYZERS,
    )


ELF_AARCH64_LINUX = _linux_elf_target("elf-aarch64-linux", AARCH64_LINUX)
ELF_AMD64_LINUX = _linux_elf_target("elf-amd64-linux", AMD64_LINUX)
ELF_AMD64_LINUX_RECOMP = _linux_elf_target("elf-amd64-linux-recomp", AMD64_LINUX_RECOMP)
ELF_ARM_LINUX = _linux_elf_target("elf-arm-linux", ARM_LINUX)
ELF_ARM_LINUX_RECOMP = _linux_elf_target("elf-arm-linux-recomp", ARM_LINUX_RECOMP)
ELF_X86_LINUX = _linux_elf_target("elf-x86-linux", X86_LINUX)
ELF_MIPS_LINUX = _linux_elf_target("elf-mips-linux", MIPS_LINUX)
ELF_MIPSEL_LINUX = _linux_elf_target("elf-mipsel-linux", MIPSEL_LINUX)
ELF_MIPS64_LINUX = _linux_elf_target("elf-mips64-linux", MIPS64_LINUX)
ELF_MIPS64EL_LINUX = _linux_elf_target("elf-mips64el-linux", MIPS64EL_LINUX)
ELF_PPC_LINUX = _linux_elf_target("elf-ppc-linux", PPC_LINUX)
ELF_PPC64_LINUX = _linux_elf_target("elf-ppc64-linux", PPC64_LINUX)
ELF_PPC64LE_LINUX = _linux_elf_target("elf-ppc64le-linux", PPC64LE_LINUX)
ELF_S390X_LINUX = _linux_elf_target("elf-s390x-linux", S390X_LINUX)
