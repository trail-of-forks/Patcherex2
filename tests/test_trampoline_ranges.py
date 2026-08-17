from types import SimpleNamespace

import pytest

from patcherex2.components.allocation_managers.allocation_manager import MemoryFlag
from patcherex2.components.archinfo.aarch64 import Aarch64Info
from patcherex2.components.archinfo.mips import MipsInfo
from patcherex2.components.archinfo.mips64 import Mips64Info
from patcherex2.components.utils.utils import InvalidInsertPointError, Utils
from patcherex2.patches.function_patches import ModifyFunctionPatch


class RecordingAllocationManager:
    def __init__(self):
        self.requests = []

    def allocate(self, size, **kwargs):
        self.requests.append((size, kwargs))
        return SimpleNamespace(size=size, mem_addr=0x5000)

    def free(self, block):
        raise AssertionError(f"unexpected free of {block}")


def test_aarch64_jump_reachability_matches_direct_branch_range():
    source_addr = 0x1000
    max_forward_distance = ((1 << 25) - 1) * 4

    assert Aarch64Info.jmp_max_distance == max_forward_distance
    assert Aarch64Info.is_jump_reachable(
        source_addr, source_addr + max_forward_distance
    )
    assert not Aarch64Info.is_jump_reachable(
        source_addr, source_addr + max_forward_distance + 4
    )


@pytest.mark.parametrize("archinfo", [MipsInfo, Mips64Info])
def test_mips_jump_reachability_uses_the_pc_plus_four_region(archinfo):
    source_addr = 0x0FFFFFFC

    assert archinfo.is_jump_reachable(source_addr, 0x10000000)
    assert not archinfo.is_jump_reachable(source_addr, 0x0FFFFFFC)


def test_trampoline_allocation_enforces_architecture_jump_range():
    allocation_manager = RecordingAllocationManager()
    patcher = SimpleNamespace(
        allocation_manager=allocation_manager,
        archinfo=Aarch64Info(),
        binfmt_tool=SimpleNamespace(is_position_independent=False),
    )
    utils = Utils(patcher, "unused")

    utils._allocate_trampoline(0x4000, 0x20, lambda _mem_addr: b"X" * 0x20)

    assert len(allocation_manager.requests) == 1
    _, constraints = allocation_manager.requests[0]
    assert constraints["near_addr"] == 0x4000
    assert constraints["max_dist"] == Aarch64Info.jmp_max_distance - 0x20


def test_invalid_insert_point_reports_nearby_mechanical_candidates():
    patcher = SimpleNamespace(
        binary_analyzer=SimpleNamespace(
            get_basic_block=lambda _addr: {
                "instruction_addrs": [0x1000, 0x1002, 0x1004, 0x1006],
            }
        )
    )
    utils = Utils(patcher, "unused")
    utils.is_valid_insert_point = lambda candidate: candidate in {0x1000, 0x1002}

    with pytest.raises(InvalidInsertPointError) as exc_info:
        utils.insert_trampoline_code(0x1004, "nop")

    assert exc_info.value.addr == 0x1004
    assert exc_info.value.candidates == (0x1002, 0x1000)
    assert "0x1002, 0x1000" in str(exc_info.value)


def test_explicit_trampoline_rejects_unreachable_detour():
    patcher = SimpleNamespace(archinfo=Aarch64Info())
    utils = Utils(patcher, "unused")
    utils.get_instrs_to_be_moved = lambda *_args, **_kwargs: ("nop", 4)
    utils._build_trampoline_bytes = lambda *_args, **_kwargs: b"X" * 0x20

    with pytest.raises(ValueError, match="exceeds architecture maximum distance"):
        utils.insert_trampoline_code(
            0x1000,
            "nop",
            force_insert=True,
            detour_pos=0x1000 + Aarch64Info.jmp_max_distance,
        )


def make_function_patch_patcher(allocation_addr):
    allocation_requests = []
    file_updates = []

    def allocate(size, **kwargs):
        allocation_requests.append((size, kwargs))
        return SimpleNamespace(mem_addr=allocation_addr, file_addr=0x2000)

    patcher = SimpleNamespace(
        allocation_manager=SimpleNamespace(allocate=allocate),
        archinfo=Aarch64Info(),
        assembler=SimpleNamespace(assemble=lambda *_args, **_kwargs: b"JUMP"),
        binary_analyzer=SimpleNamespace(
            get_function=lambda _name: {"addr": 0x1000, "size": 0x10},
            is_thumb=lambda _addr: False,
            mem_addr_to_file_offset=lambda addr: addr,
        ),
        binfmt_tool=SimpleNamespace(
            is_position_independent=False,
            update_binary_content=lambda offset, content: file_updates.append(
                (offset, content)
            ),
        ),
        compiler=SimpleNamespace(
            compile=lambda *_args, **_kwargs: b"C" * 0x40,
        ),
    )
    patcher.utils = Utils(patcher, "unused")
    return patcher, allocation_requests, file_updates


def test_modify_function_allocation_enforces_jump_range():
    target_addr = 0x1000 + Aarch64Info.jmp_max_distance
    patcher, allocation_requests, file_updates = make_function_patch_patcher(
        target_addr
    )

    ModifyFunctionPatch("target", "return 0;").apply(patcher)

    assert len(allocation_requests) == 1
    _, constraints = allocation_requests[0]
    assert constraints["near_addr"] == 0x1000
    assert constraints["max_dist"] == Aarch64Info.jmp_max_distance
    assert file_updates


def test_modify_function_rejects_unreachable_explicit_detour():
    patcher, allocation_requests, file_updates = make_function_patch_patcher(0)
    detour_pos = 0x1000 + Aarch64Info.jmp_max_distance + 4

    with pytest.raises(ValueError, match="exceeds architecture maximum distance"):
        ModifyFunctionPatch("target", "return 0;", detour_pos=detour_pos).apply(patcher)

    assert allocation_requests == []
    assert file_updates == []


class ResizingAllocationManager:
    def __init__(self):
        self.requests = []
        self.freed = []

    def allocate(self, size, **kwargs):
        self.requests.append((size, kwargs))
        index = len(self.requests)
        return SimpleNamespace(
            mem_addr=index * 0x1000,
            file_addr=index * 0x100,
            size=size,
            is_free=False,
        )

    def free(self, block):
        block.is_free = True
        self.freed.append(block)


def test_trampoline_allocation_reassembles_until_final_bytes_fit():
    allocation_manager = ResizingAllocationManager()
    patcher = SimpleNamespace(
        allocation_manager=allocation_manager,
        archinfo=SimpleNamespace(alignment=1),
        binfmt_tool=SimpleNamespace(is_position_independent=True),
    )
    utils = Utils(patcher, "unused")
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
