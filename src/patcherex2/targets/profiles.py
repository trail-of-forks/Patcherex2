from __future__ import annotations

from contextlib import AbstractContextManager

import archinfo
import capstone

from patcherex2.components.allocation_manager import (
    AllocationManager,
    Allocator,
)
from patcherex2.components.arch import ArchitectureInfo
from patcherex2.components.arch.aarch64 import AARCH64
from patcherex2.components.arch.amd64 import AMD64
from patcherex2.components.arch.arm import ARM
from patcherex2.components.arch.mips import MIPS, MIPSEL
from patcherex2.components.arch.mips64 import MIPS64, MIPS64EL
from patcherex2.components.arch.ppc import PPC
from patcherex2.components.arch.ppc64 import PPC64, PPC64LE
from patcherex2.components.arch.ppc_vle import PPC_VLE
from patcherex2.components.arch.riscv32 import RISCV32
from patcherex2.components.arch.s390x import S390X
from patcherex2.components.arch.sparc import SPARC
from patcherex2.components.arch.x86 import X86
from patcherex2.components.assembler import Assembler
from patcherex2.components.assembler.bcc import BccAssemblyBackend
from patcherex2.components.assembler.keystone import KeystoneAssemblyBackend, keystone
from patcherex2.components.assembler.keystone_arm import KeystoneArmAssemblyBackend
from patcherex2.components.assembler.keystone_s390x import S390xAssemblyBackend
from patcherex2.components.assembler.keystone_sparc import (
    KeystoneSparcAssemblyBackend,
)
from patcherex2.components.assembler.nyxstone import NyxstoneAssemblyBackend
from patcherex2.components.assembler.ppc_vle import PpcVleAssemblyBackend
from patcherex2.components.binary_analyzer import BinaryAnalyzer
from patcherex2.components.binary_analyzer.angr import AngrAnalyzer
from patcherex2.components.binary_analyzer.ghidra import GhidraAnalyzer
from patcherex2.components.binary_analyzer.ida import IDAAnalyzer
from patcherex2.components.compilers import Compiler
from patcherex2.components.compilers.arm import ArmCompiler
from patcherex2.components.compilers.bcc import BccObjectCompiler
from patcherex2.components.compilers.clang import ClangObjectCompiler
from patcherex2.components.compilers.elf import create_elf_compiler
from patcherex2.components.compilers.llvm_recomp import (
    LLVMRecompObjectCompiler,
)
from patcherex2.components.compilers.ppc_vle import PpcVleObjectCompiler
from patcherex2.components.disassemblers.capstone import Capstone
from patcherex2.components.disassemblers.capstone_arm import CapstoneArm
from patcherex2.components.disassemblers.disassembler import Disassembler
from patcherex2.components.disassemblers.nyxstone import (
    Nyxstone as NyxstoneDisassembler,
)
from patcherex2.components.disassemblers.ppc_vle import PpcVle as PpcVleDisassembler
from patcherex2.components.image import ImageBackend
from patcherex2.components.image.elf import ElfImageBackend
from patcherex2.components.image.ihex import IHexImageBackend
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.components.utils.utils import Utils
from patcherex2.targets.target import (
    ArchitectureProfile,
    AssemblerBuilder,
    BinaryAnalyzerBuilder,
    CompilerBuilder,
    ComponentFactory,
    DisassemblerBuilder,
    ImageProfile,
    UtilsBuilder,
)

_DEFAULT_CLANG_VERSION = 15


def _keystone_factory(arch: int, mode: int) -> ComponentFactory[AssemblerBuilder]:
    def build(symbol_resolver: SymbolResolver) -> Assembler:
        return Assembler(symbol_resolver, KeystoneAssemblyBackend(arch, mode))

    return ComponentFactory(role="assembler", default="keystone", choices={"keystone": build})


def _capstone_factory(
    arch: int,
    mode: int,
    *,
    numeric_ppc_registers: bool = False,
) -> ComponentFactory[DisassemblerBuilder]:
    def build() -> Capstone:
        disassembler = Capstone(arch, mode)
        if numeric_ppc_registers:
            disassembler.cs.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME
        return disassembler

    return ComponentFactory(role="disassembler", default="capstone", choices={"capstone": build})


def _clang_factory(
    flags: tuple[str, ...],
    *,
    arm: bool = False,
    default_version: int = _DEFAULT_CLANG_VERSION,
    include_clang19: bool = False,
) -> ComponentFactory[CompilerBuilder]:
    def for_version(version: int) -> CompilerBuilder:
        def build(
            *,
            architecture: ArchitectureInfo,
            image: ImageBackend,
            symbol_resolver: SymbolResolver,
            assembler: Assembler,
            disassembler: Disassembler,
        ) -> Compiler:
            object_compiler = ClangObjectCompiler(
                version,
                flags,
                image.is_position_independent,
                architecture.non_pic_compiler_flags,
            )
            compiler = create_elf_compiler(
                architecture=architecture,
                symbol_resolver=symbol_resolver,
                object_compiler=object_compiler,
                linker=object_compiler.linker,
                position_independent=image.is_position_independent,
            )
            if not arm:
                return compiler
            return ArmCompiler(compiler, assembler, disassembler, symbol_resolver)

        return build

    choices: dict[str, CompilerBuilder] = {"clang": for_version(default_version)}
    if include_clang19:
        choices["clang19"] = for_version(19)
    return ComponentFactory(role="compiler", default="clang", choices=choices)


def _recomp_factory(
    flags: tuple[str, ...], *, arm: bool = False
) -> ComponentFactory[CompilerBuilder]:
    def build(
        *,
        architecture: ArchitectureInfo,
        image: ImageBackend,
        symbol_resolver: SymbolResolver,
        assembler: Assembler,
        disassembler: Disassembler,
    ) -> Compiler:
        object_compiler = LLVMRecompObjectCompiler(
            _DEFAULT_CLANG_VERSION,
            flags,
            image.is_position_independent,
            architecture.non_pic_compiler_flags,
        )
        compiler = create_elf_compiler(
            architecture=architecture,
            symbol_resolver=symbol_resolver,
            object_compiler=object_compiler,
            linker=object_compiler.linker,
            position_independent=image.is_position_independent,
            resolve_address_symbols=True,
        )
        if not arm:
            return compiler
        return ArmCompiler(compiler, assembler, disassembler, symbol_resolver)

    return ComponentFactory(role="compiler", default="llvm_recomp", choices={"llvm_recomp": build})


def _utils_factory() -> ComponentFactory[UtilsBuilder]:
    def build(
        architecture: ArchitectureInfo,
        assembler: Assembler,
        disassembler: Disassembler,
        compiler: Compiler,
        binary_analyzer: BinaryAnalyzer,
        allocation_manager: Allocator,
        image: ImageBackend,
    ) -> Utils:
        return Utils(
            architecture=architecture,
            assembler=assembler,
            disassembler=disassembler,
            compiler=compiler,
            binary_analyzer=binary_analyzer,
            allocation_manager=allocation_manager,
            image=image,
        )

    return ComponentFactory(role="utilities", default="default", choices={"default": build})


def architecture_profile(
    name: str,
    architecture_info: ArchitectureInfo,
    assembler: ComponentFactory[AssemblerBuilder],
    compiler: ComponentFactory[CompilerBuilder],
    disassembler: ComponentFactory[DisassemblerBuilder],
) -> ArchitectureProfile:
    return ArchitectureProfile(
        name=name,
        info=architecture_info,
        assembler=assembler,
        compiler=compiler,
        disassembler=disassembler,
        utilities=_utils_factory(),
    )


def standard_analyzer_factory(*, default: str = "angr") -> ComponentFactory[BinaryAnalyzerBuilder]:
    def angr_builder(
        binary_path: str,
        _image: ImageBackend,
    ) -> AbstractContextManager[AngrAnalyzer]:
        return AngrAnalyzer.load_binary(binary_path)

    def ghidra_builder(
        binary_path: str,
        _image: ImageBackend,
    ) -> AbstractContextManager[GhidraAnalyzer]:
        return GhidraAnalyzer.load_binary(binary_path)

    def ida_builder(
        binary_path: str,
        _image: ImageBackend,
    ) -> AbstractContextManager[IDAAnalyzer]:
        return IDAAnalyzer.load_binary(binary_path)

    return ComponentFactory(
        role="binary analyzer",
        default=default,
        choices={
            "angr": angr_builder,
            "ghidra": ghidra_builder,
            "ida": ida_builder,
        },
    )


def _elf_backend(binary_path: str) -> ElfImageBackend:
    return ElfImageBackend(binary_path)


def _ihex_backend(binary_path: str) -> IHexImageBackend:
    return IHexImageBackend(binary_path)


def _allocator(
    binary_analyzer: BinaryAnalyzer,
    image: ImageBackend,
) -> AllocationManager:
    return AllocationManager(
        binary_analyzer=binary_analyzer,
        image=image,
    )


ELF_IMAGE = ImageProfile(
    name="elf",
    backend=ComponentFactory(role="image backend", default="elf", choices={"elf": _elf_backend}),
    allocator=ComponentFactory(
        role="allocation manager",
        default="default",
        choices={"default": _allocator},
    ),
)

IHEX_IMAGE = ImageProfile(
    name="ihex",
    backend=ComponentFactory(role="image backend", default="ihex", choices={"ihex": _ihex_backend}),
    allocator=ComponentFactory(
        role="allocation manager",
        default="default",
        choices={"default": _allocator},
    ),
)

AMD64_LINUX = architecture_profile(
    "amd64-linux",
    AMD64,
    _keystone_factory(
        keystone.KS_ARCH_X86,
        keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_64,
    ),
    _clang_factory(
        ("-target", "x86_64-linux-gnu"),
        include_clang19=True,
    ),
    _capstone_factory(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_64,
    ),
)

AMD64_LINUX_RECOMP = AMD64_LINUX.model_copy(
    update={
        "name": "amd64-linux-recomp",
        "compiler": _recomp_factory(("-target", "x86_64-linux-gnu")),
    }
)

X86_LINUX = architecture_profile(
    "x86-linux",
    X86,
    _keystone_factory(
        keystone.KS_ARCH_X86,
        keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_32,
    ),
    _clang_factory(("-target", "i386-linux-gnu")),
    _capstone_factory(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_32,
    ),
)

AARCH64_LINUX = architecture_profile(
    "aarch64-linux",
    AARCH64,
    _keystone_factory(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
    _clang_factory(
        ("-target", "aarch64-linux-gnu"),
        include_clang19=True,
    ),
    _capstone_factory(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN),
)


def _arm_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    return Assembler(symbol_resolver, KeystoneArmAssemblyBackend())


def _arm_disassembler() -> CapstoneArm:
    return CapstoneArm()


ARM_LINUX = architecture_profile(
    "arm-linux",
    ARM,
    ComponentFactory(
        role="assembler",
        default="keystone",
        choices={"keystone": _arm_assembler},
    ),
    _clang_factory(
        ("-target", "arm-linux-gnueabihf"),
        arm=True,
        include_clang19=True,
    ),
    ComponentFactory(
        role="disassembler",
        default="capstone",
        choices={"capstone": _arm_disassembler},
    ),
)

ARM_BARE = ARM_LINUX.model_copy(update={"name": "arm-bare"})

ARM_LINUX_RECOMP = ARM_LINUX.model_copy(
    update={
        "name": "arm-linux-recomp",
        "compiler": _recomp_factory(
            ("-target", "arm-linux-gnueabihf"),
            arm=True,
        ),
    }
)


def _mips_profile(
    name: str,
    architecture_info: ArchitectureInfo,
    assembler_mode: int,
    disassembler_mode: int,
    target_triple: str,
) -> ArchitectureProfile:
    return architecture_profile(
        name,
        architecture_info,
        _keystone_factory(keystone.KS_ARCH_MIPS, assembler_mode),
        _clang_factory(
            (target_triple,),
        ),
        _capstone_factory(capstone.CS_ARCH_MIPS, disassembler_mode),
    )


MIPS_LINUX = _mips_profile(
    "mips-linux",
    MIPS,
    keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_MIPS32,
    capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_MIPS32,
    "--target=mips-linux-gnu",
)
MIPSEL_LINUX = _mips_profile(
    "mipsel-linux",
    MIPSEL,
    keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_MIPS32,
    capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_MIPS32,
    "--target=mipsel-linux-gnu",
)
MIPS64_LINUX = _mips_profile(
    "mips64-linux",
    MIPS64,
    keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_MIPS64,
    capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_MIPS64,
    "--target=mips64-linux-gnuabi64",
)
MIPS64EL_LINUX = _mips_profile(
    "mips64el-linux",
    MIPS64EL,
    keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_MIPS64,
    capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_MIPS64,
    "--target=mips64el-linux-gnuabi64",
)


def _ppc_profile(
    name: str,
    architecture_info: ArchitectureInfo,
    assembler_mode: int,
    disassembler_mode: int,
    target_triple: str,
) -> ArchitectureProfile:
    return architecture_profile(
        name,
        architecture_info,
        _keystone_factory(keystone.KS_ARCH_PPC, assembler_mode),
        _clang_factory(("-target", target_triple)),
        _capstone_factory(
            capstone.CS_ARCH_PPC,
            disassembler_mode,
            numeric_ppc_registers=True,
        ),
    )


PPC_LINUX = _ppc_profile(
    "ppc-linux",
    PPC,
    keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_PPC32,
    capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_32,
    "powerpc-linux-gnu",
)
PPC64_LINUX = _ppc_profile(
    "ppc64-linux",
    PPC64,
    keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_PPC64,
    capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_64,
    "powerpc64-linux-gnu",
)
PPC64LE_LINUX = _ppc_profile(
    "ppc64le-linux",
    PPC64LE,
    keystone.KS_MODE_LITTLE_ENDIAN + keystone.KS_MODE_PPC64,
    capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_64,
    "powerpc64le-linux-gnu",
)


def _s390x_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    return Assembler(
        symbol_resolver,
        S390xAssemblyBackend(
            keystone.KS_ARCH_SYSTEMZ,
            keystone.KS_MODE_BIG_ENDIAN,
        ),
    )


S390X_LINUX = architecture_profile(
    "s390x-linux",
    S390X,
    ComponentFactory(
        role="assembler",
        default="keystone",
        choices={"keystone": _s390x_assembler},
    ),
    _clang_factory(
        ("-target", "s390x-linux-gnu"),
        default_version=19,
    ),
    _capstone_factory(capstone.CS_ARCH_SYSZ, capstone.CS_MODE_BIG_ENDIAN),
)


def _sparc_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    backend = KeystoneSparcAssemblyBackend(
        keystone.KS_ARCH_SPARC,
        keystone.KS_MODE_SPARC32 + keystone.KS_MODE_BIG_ENDIAN,
    )
    return Assembler(symbol_resolver, backend)


def _bcc_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    return Assembler(symbol_resolver, BccAssemblyBackend())


def _bcc_compiler(
    *,
    architecture: ArchitectureInfo,
    image: ImageBackend,
    symbol_resolver: SymbolResolver,
    assembler: Assembler,
    disassembler: Disassembler,
) -> Compiler:
    del assembler, disassembler
    object_compiler = BccObjectCompiler(
        image.is_position_independent,
        architecture.non_pic_compiler_flags,
    )
    return create_elf_compiler(
        architecture=architecture,
        symbol_resolver=symbol_resolver,
        object_compiler=object_compiler,
        linker=object_compiler.linker,
        position_independent=image.is_position_independent,
    )


SPARC_BARE = architecture_profile(
    "sparc-bare",
    SPARC,
    ComponentFactory(
        role="assembler",
        default="keystone",
        choices={"keystone": _sparc_assembler, "bcc": _bcc_assembler},
    ),
    ComponentFactory(role="compiler", default="bcc", choices={"bcc": _bcc_compiler}),
    _capstone_factory(capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN),
)


def _ppc_vle_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    return Assembler(symbol_resolver, PpcVleAssemblyBackend())


def _ppc_vle_compiler(
    *,
    architecture: ArchitectureInfo,
    image: ImageBackend,
    symbol_resolver: SymbolResolver,
    assembler: Assembler,
    disassembler: Disassembler,
) -> Compiler:
    del assembler, disassembler
    object_compiler = PpcVleObjectCompiler(
        image.is_position_independent,
        architecture.non_pic_compiler_flags,
    )
    return create_elf_compiler(
        architecture=architecture,
        symbol_resolver=symbol_resolver,
        object_compiler=object_compiler,
        linker=object_compiler.linker,
        position_independent=image.is_position_independent,
    )


def _ppc_vle_disassembler() -> PpcVleDisassembler:
    return PpcVleDisassembler()


PPC_VLE_BARE = architecture_profile(
    "ppc-vle-bare",
    PPC_VLE,
    ComponentFactory(
        role="assembler",
        default="default",
        choices={"default": _ppc_vle_assembler},
    ),
    ComponentFactory(
        role="compiler",
        default="default",
        choices={"default": _ppc_vle_compiler},
    ),
    ComponentFactory(
        role="disassembler",
        default="default",
        choices={"default": _ppc_vle_disassembler},
    ),
)


def _riscv_nyxstone_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    return Assembler(symbol_resolver, NyxstoneAssemblyBackend("riscv32", "", "+c"))


def _riscv_keystone_assembler(symbol_resolver: SymbolResolver) -> Assembler:
    backend = KeystoneAssemblyBackend(
        keystone.KS_ARCH_RISCV,  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
        keystone.KS_MODE_RISCV32,  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    )
    return Assembler(symbol_resolver, backend)


def _riscv_nyxstone_disassembler() -> NyxstoneDisassembler:
    return NyxstoneDisassembler("riscv32", "", "+c")


def _riscv_capstone_disassembler() -> Capstone:
    return Capstone(
        capstone.CS_ARCH_RISCV,
        capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC,
    )


RISCV32_BARE = architecture_profile(
    "riscv32-bare",
    RISCV32,
    ComponentFactory(
        role="assembler",
        default="nyxstone",
        choices={
            "nyxstone": _riscv_nyxstone_assembler,
            "keystone": _riscv_keystone_assembler,
        },
    ),
    _clang_factory(("-target", "riscv32-unknown-elf")),
    ComponentFactory(
        role="disassembler",
        default="nyxstone",
        choices={
            "nyxstone": _riscv_nyxstone_disassembler,
            "capstone": _riscv_capstone_disassembler,
        },
    ),
)


def ppc_vle_analyzer_factory() -> ComponentFactory[BinaryAnalyzerBuilder]:
    def build(binary_path: str, _image: ImageBackend) -> AbstractContextManager[AngrAnalyzer]:
        return AngrAnalyzer.load_binary(
            binary_path,
            angr_kwargs={
                "arch": archinfo.ArchPcode("PowerPC:BE:32:MPC8270"),
                "auto_load_libs": False,
                "load_debug_info": True,
            },
            angr_cfg_kwargs={
                "normalize": True,
                "data_references": True,
                "force_smart_scan": False,
                "force_complete_scan": False,
            },
        )

    return ComponentFactory(role="binary analyzer", default="angr", choices={"angr": build})
