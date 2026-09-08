import sys
from collections.abc import Callable
from typing import cast

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import pytest

from patcherex2.components.allocation_manager import MappedBlock, MemoryFlag
from patcherex2.components.arch.aarch64 import AARCH64
from patcherex2.components.arch.mips import MIPS
from patcherex2.components.arch.mips64 import MIPS64
from patcherex2.components.binary_analyzer import BasicBlock, FunctionInfo
from patcherex2.components.symbol_resolver import SymbolResolver
from patcherex2.components.utils.utils import (
    InvalidInsertPointError,
    Utils,
)
from patcherex2.patch.function import ModifyFunctionPatch
from patcherex2.session import PatchSession
from patcherex2.targets import ELF_AARCH64_LINUX
from tests.support.fakes import (
    FakeAllocator,
    FakeBinaryAnalyzer,
    FakeCompiler,
    FakeDisassembler,
    FakeImageBackend,
    make_assembler,
)


def make_utils(
    *,
    architecture,
    allocation_manager=None,
    assembler=None,
    disassembler=None,
    compiler=None,
    binary_analyzer=None,
    image=None,
    utils_type: type[Utils] = Utils,
):
    binary_analyzer = binary_analyzer or FakeBinaryAnalyzer()
    return utils_type(
        architecture=architecture,
        assembler=assembler or make_assembler(lambda *_args, **_kwargs: b""),
        disassembler=disassembler or FakeDisassembler(),
        compiler=compiler or FakeCompiler(),
        binary_analyzer=binary_analyzer,
        allocation_manager=allocation_manager or FakeAllocator(),
        image=image or FakeImageBackend(),
    )


class CandidateReportingUtils(Utils):
    @override
    def _get_instrs_to_be_moved_from_block(
        self,
        addr: int,
        basic_block: BasicBlock,
        ignore_unmovable: bool = False,
    ) -> tuple[str, int] | None:
        del basic_block, ignore_unmovable
        return ("nop", 4) if addr in {0x1000, 0x1002} else None


class FixedTrampolineUtils(Utils):
    @override
    def get_instrs_to_be_moved(
        self,
        addr: int,
        ignore_unmovable: bool = False,
        basic_block: BasicBlock | None = None,
    ) -> tuple[str, int] | None:
        del addr, ignore_unmovable, basic_block
        return ("nop", 4)

    @override
    def _build_trampoline_bytes(
        self,
        addr: int,
        mem_addr: int,
        instrs: str,
        moved_instrs: str,
        jump_back_instr: str,
        jump_back_target: int,
        symbols: dict[str, int],
        is_c: bool,
        asm_header: str,
        asm_footer: str,
    ) -> bytes:
        del (
            addr,
            mem_addr,
            instrs,
            moved_instrs,
            jump_back_instr,
            jump_back_target,
            symbols,
            is_c,
            asm_header,
            asm_footer,
        )
        return b"X" * 0x20


def test_aarch64_jump_reachability_matches_direct_branch_range():
    source_addr = 0x1000
    max_forward_distance = ((1 << 25) - 1) * 4

    assert AARCH64.jmp_max_distance == max_forward_distance
    assert AARCH64.is_jump_reachable(source_addr, source_addr + max_forward_distance)
    assert not AARCH64.is_jump_reachable(source_addr, source_addr + max_forward_distance + 4)


@pytest.mark.parametrize("archinfo", [MIPS, MIPS64])
def test_mips_jump_reachability_uses_the_pc_plus_four_region(archinfo):
    source_addr = 0x0FFFFFFC

    assert archinfo.is_jump_reachable(source_addr, 0x10000000)
    assert not archinfo.is_jump_reachable(source_addr, 0x0FFFFFFC)


def test_trampoline_allocation_enforces_architecture_jump_range():
    allocation_manager = FakeAllocator()
    utils = make_utils(
        architecture=AARCH64,
        allocation_manager=allocation_manager,
    )

    utils._allocate_trampoline(0x4000, 0x20, lambda _mem_addr: b"X" * 0x20)

    assert len(allocation_manager.requests) == 1
    _, constraints = allocation_manager.requests[0]
    assert constraints["near_addr"] == 0x4000
    max_distance = AARCH64.jmp_max_distance
    assert max_distance is not None
    assert constraints["max_dist"] == max_distance - 0x20


def test_invalid_insert_point_reports_nearby_mechanical_candidates():
    calls = 0
    block = BasicBlock(
        start=0x1000,
        size=8,
        instruction_addrs=(0x1000, 0x1002, 0x1004, 0x1006),
    )

    def get_basic_block(_addr):
        nonlocal calls
        calls += 1
        return block

    binary_analyzer = FakeBinaryAnalyzer(get_block=get_basic_block)
    utils = make_utils(
        architecture=AARCH64,
        binary_analyzer=binary_analyzer,
        utils_type=CandidateReportingUtils,
    )

    with pytest.raises(InvalidInsertPointError) as exc_info:
        utils.insert_trampoline_code(0x1004, "nop")

    assert calls == 1
    assert exc_info.value.addr == 0x1004
    assert exc_info.value.candidates == (0x1002, 0x1000)
    assert "0x1002, 0x1000" in str(exc_info.value)


def test_explicit_trampoline_rejects_unreachable_detour():
    binary_analyzer = FakeBinaryAnalyzer(
        get_block=lambda _addr: BasicBlock(
            start=0x1000,
            size=4,
            instruction_addrs=(0x1000,),
        )
    )
    utils = make_utils(
        architecture=AARCH64,
        binary_analyzer=binary_analyzer,
        utils_type=FixedTrampolineUtils,
    )

    max_distance = AARCH64.jmp_max_distance
    assert max_distance is not None
    with pytest.raises(ValueError, match="exceeds architecture maximum distance"):
        utils.insert_trampoline_code(
            0x1000,
            "nop",
            force_insert=True,
            detour_pos=0x1000 + max_distance,
        )


def make_function_patch_patcher(allocation_addr):
    def allocate(size, _options):
        return MappedBlock(
            addr=allocation_addr,
            file_addr=0x2000,
            size=size,
            is_free=False,
        )

    allocation_manager = FakeAllocator(allocate)
    binary_analyzer = FakeBinaryAnalyzer(
        get_function=lambda _name: FunctionInfo(addr=0x1000, size=0x10),
        is_thumb=lambda _addr: False,
        map_address=lambda addr: addr,
    )
    image = FakeImageBackend()

    class FakeFunctionPatchContext:
        def __init__(self) -> None:
            self.allocation_manager = allocation_manager
            self.archinfo = AARCH64
            self.assembler = make_assembler(lambda *_args, **_kwargs: b"JUMP", binary_analyzer)
            self.binary_analyzer = binary_analyzer
            self.image = image
            self.compiler = FakeCompiler(lambda *_args, **_kwargs: b"C" * 0x40)
            self.utils: Utils

    patcher = FakeFunctionPatchContext()
    patcher.utils = make_utils(
        architecture=patcher.archinfo,
        allocation_manager=patcher.allocation_manager,
        assembler=patcher.assembler,
        compiler=patcher.compiler,
        binary_analyzer=patcher.binary_analyzer,
        image=patcher.image,
    )
    return cast(PatchSession, patcher), allocation_manager.requests, image


def test_modify_function_allocation_uses_full_one_way_jump_range():
    max_distance = AARCH64.jmp_max_distance
    assert max_distance is not None
    target_addr = 0x1000 + max_distance
    patcher, allocation_requests, image = make_function_patch_patcher(target_addr)

    ModifyFunctionPatch("target", "return 0;").apply(patcher)

    assert len(allocation_requests) == 1
    _, constraints = allocation_requests[0]
    assert constraints["near_addr"] == 0x1000
    assert constraints["max_dist"] == max_distance
    address_validator = cast(Callable[[int], bool], constraints["address_validator"])
    assert address_validator(target_addr)
    assert image.updates


def test_modify_function_rejects_unreachable_explicit_detour():
    patcher, allocation_requests, image = make_function_patch_patcher(0)
    max_distance = AARCH64.jmp_max_distance
    assert max_distance is not None
    detour_pos = 0x1000 + max_distance + 4

    with pytest.raises(ValueError, match="exceeds architecture maximum distance"):
        ModifyFunctionPatch("target", "return 0;", detour_pos=detour_pos).apply(patcher)

    assert allocation_requests == []
    assert image.updates == []


def test_trampoline_allocation_reassembles_until_final_bytes_fit():
    allocation_index = 0

    def allocate(size, _options):
        nonlocal allocation_index
        allocation_index += 1
        return MappedBlock(
            addr=allocation_index * 0x1000,
            file_addr=allocation_index * 0x100,
            size=size,
            is_free=False,
        )

    allocation_manager = FakeAllocator(allocate)
    utils = make_utils(
        architecture=AARCH64,
        allocation_manager=allocation_manager,
    )
    final_sizes = {0x1000: 26, 0x2000: 28, 0x3000: 28}

    block, content = utils._allocate_trampoline(
        0x4000,
        24,
        lambda mem_addr: b"X" * final_sizes[mem_addr],
    )

    assert [request[0] for request in allocation_manager.requests] == [24, 26, 28]
    assert len(allocation_manager.freed) == 2
    assert block.mem_addr == 0x3000
    assert block.size == len(content) == 28
    for _, kwargs in allocation_manager.requests:
        assert kwargs["flag"] == MemoryFlag.RX
        assert kwargs["near_addr"] == 0x4000
    max_distance = AARCH64.jmp_max_distance
    assert max_distance is not None
    assert [kwargs["max_dist"] for _, kwargs in allocation_manager.requests] == [
        max_distance - 24,
        max_distance - 26,
        max_distance - 28,
    ]


def test_relocated_branch_is_rejected_when_assembler_wraps_target():
    binary_analyzer = FakeBinaryAnalyzer()
    architecture = ELF_AARCH64_LINUX.architecture
    assembler = architecture.assembler.select(None)(SymbolResolver(binary_analyzer))
    disassembler = architecture.disassembler.select(None)()
    utils = make_utils(
        architecture=architecture.info,
        assembler=assembler,
        disassembler=disassembler,
        binary_analyzer=binary_analyzer,
    )
    source_addr = 0x10000
    original = assembler.assemble("b.eq 0x20000", source_addr)
    moved_instrs = disassembler.to_asm_string(disassembler.disassemble(original, source_addr)[0])
    relocated_addr = 0x80000000
    relocated = assembler.assemble(moved_instrs, relocated_addr)

    with pytest.raises(ValueError, match="changes their semantics"):
        utils._validate_relocated_instructions(
            relocated,
            relocated_addr,
            moved_instrs,
            is_thumb=False,
        )
