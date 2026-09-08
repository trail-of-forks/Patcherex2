from collections.abc import Callable
from typing import cast

import pytest

from patcherex2.components.allocation_manager import MappedBlock
from patcherex2.components.arch.x86 import X86
from patcherex2.components.binary_analyzer import FunctionInfo
from patcherex2.components.utils.utils import Utils
from patcherex2.patch.function import (
    InsertFunctionPatch,
    ModifyFunctionPatch,
)
from patcherex2.patch.instruction import (
    InsertInstructionPatch,
    InstructionPatchLanguage,
    RemoveInstructionPatch,
)
from patcherex2.patch.raw import AddressType, ModifyRawBytesPatch
from patcherex2.session import PatchSession
from tests.support.fakes import (
    FakeAllocator,
    FakeBinaryAnalyzer,
    FakeCompiler,
    FakeDisassembler,
    FakeImageBackend,
    make_assembler,
)


class FakePatchContext:
    """Explicit component graph consumed by patch implementations."""

    def __init__(
        self,
        *,
        image: FakeImageBackend,
        architecture=X86,
        binary_analyzer: FakeBinaryAnalyzer | None = None,
        assembler=None,
        compiler: FakeCompiler | None = None,
        allocation_manager: FakeAllocator | None = None,
        symbols: dict[str, int] | None = None,
        added_functions: list[str] | None = None,
        utils: object | None = None,
    ) -> None:
        self.image = image
        self.archinfo = architecture
        self.binary_analyzer = binary_analyzer or FakeBinaryAnalyzer()
        self.assembler = assembler or make_assembler(lambda *_args, **_kwargs: b"")
        self.compiler = compiler or FakeCompiler()
        self.allocation_manager = allocation_manager or FakeAllocator()
        self.symbols = {} if symbols is None else symbols
        self.added_functions = [] if added_functions is None else added_functions
        self.utils = utils


class FakePatchUtils:
    def __init__(
        self,
        allocate_generated_code: Callable[..., tuple[MappedBlock, bytes]],
        insert_trampoline_code: Callable[..., None],
    ) -> None:
        self.allocate_generated_code = allocate_generated_code
        self.insert_trampoline_code = insert_trampoline_code


def as_patcherex(value: FakePatchContext) -> PatchSession:
    """Type a focused component graph as the patch API's aggregate context."""
    return cast(PatchSession, value)


def make_utils(
    *,
    architecture=X86,
    allocation_manager=None,
    assembler=None,
    disassembler=None,
    compiler=None,
    binary_analyzer=None,
    image=None,
    added_functions=None,
):
    binary_analyzer = binary_analyzer or FakeBinaryAnalyzer()
    return Utils(
        architecture=architecture,
        assembler=assembler or make_assembler(lambda *_args, **_kwargs: b""),
        disassembler=disassembler or FakeDisassembler(),
        compiler=compiler or FakeCompiler(),
        binary_analyzer=binary_analyzer,
        allocation_manager=allocation_manager or FakeAllocator(),
        image=image or FakeImageBackend(),
        added_functions=added_functions,
    )


def test_utils_default_added_functions_are_not_shared():
    first = make_utils()
    second = make_utils()

    first.added_functions.append("0x1000")

    assert first.added_functions == ["0x1000"]
    assert second.added_functions == []


def test_raw_patch_uses_file_address_directly():
    image = FakeImageBackend()
    patcher = FakePatchContext(image=image)

    ModifyRawBytesPatch(0x20, b"data", addr_type=AddressType.FILE).apply(as_patcherex(patcher))

    assert image.updates == [(0x20, b"data")]


def test_raw_patch_maps_memory_address_by_default():
    image = FakeImageBackend()
    patcher = FakePatchContext(
        image=image,
        binary_analyzer=FakeBinaryAnalyzer(map_address=lambda address: address - 0x1000),
    )

    ModifyRawBytesPatch(0x1020, b"data").apply(as_patcherex(patcher))

    assert image.updates == [(0x20, b"data")]


def test_instruction_patch_defaults_to_assembly():
    patch = InsertInstructionPatch(0x1000, "nop")

    assert patch.language is InstructionPatchLanguage.ASM


def test_instruction_patch_rejects_string_language():
    with pytest.raises(TypeError, match="language must be an InstructionPatchLanguage"):
        InsertInstructionPatch(
            0x1000,
            "return 0;",
            language=cast(InstructionPatchLanguage, "C"),
        )


def make_resizing_allocator() -> FakeAllocator:
    allocation_index = 0

    def allocate(size, options):
        nonlocal allocation_index
        allocation_index += 1
        mem_addr = allocation_index * 0x1000
        return MappedBlock(
            addr=mem_addr,
            file_addr=mem_addr // 0x10,
            size=size,
            is_free=False,
        )

    return FakeAllocator(allocate)


def test_remove_instruction_count_uses_decoded_instruction_lengths():
    image = FakeImageBackend()
    patcher = FakePatchContext(
        image=image,
        architecture=X86,
        binary_analyzer=FakeBinaryAnalyzer(
            get_instructions=lambda _addr, _num_instr: b"\x01\x02\x03\x04\x05",
            map_address=lambda addr: addr - 0x1000,
        ),
    )

    patch = RemoveInstructionPatch(0x1010, num_instr=2)
    patch.apply(as_patcherex(patcher))

    assert patch.num_bytes is None
    assert image.updates == [(0x10, b"\x90" * 5)]


def test_remove_instruction_bytes_replaces_exact_range_without_decoding():
    image = FakeImageBackend()

    def reject_decode(*_args, **_kwargs):
        raise AssertionError("num_bytes must not decode instructions")

    patcher = FakePatchContext(
        image=image,
        architecture=X86,
        binary_analyzer=FakeBinaryAnalyzer(
            get_instructions=reject_decode,
            map_address=lambda addr: addr - 0x1000,
        ),
    )

    RemoveInstructionPatch(0x1010, num_bytes=1).apply(as_patcherex(patcher))

    assert image.updates == [(0x10, b"\x90")]


def test_remove_instruction_rejects_ambiguous_count():
    with pytest.raises(ValueError, match="either num_instr or num_bytes"):
        RemoveInstructionPatch(0x1000, num_instr=1, num_bytes=1)


def test_named_asm_patch_reassembles_until_final_address_bytes_fit():
    manager = make_resizing_allocator()
    image = FakeImageBackend()

    def assemble(_code, base=0, **_kwargs):
        return b"A" * (2 if base == 0 else 4)

    patcher = FakePatchContext(
        image=image,
        allocation_manager=manager,
        architecture=X86,
        assembler=make_assembler(assemble),
        symbols={},
    )
    patcher.utils = make_utils(
        architecture=patcher.archinfo,
        allocation_manager=manager,
        assembler=patcher.assembler,
        image=patcher.image,
    )

    InsertInstructionPatch("helper", "nop").apply(as_patcherex(patcher))

    assert [size for size, _ in manager.requests] == [2, 4]
    assert len(manager.freed) == 1
    assert patcher.symbols["helper"] == 0x2000
    assert image.updates == [(0x200, b"A" * 4)]


def test_named_c_patch_recompiles_until_final_address_bytes_fit():
    manager = make_resizing_allocator()
    image = FakeImageBackend()

    def compile_code(_code, base=0, **_kwargs):
        return b"C" * (3 if base == 0 else 7)

    added_functions: list[str] = []
    patcher = FakePatchContext(
        image=image,
        allocation_manager=manager,
        architecture=X86,
        compiler=FakeCompiler(compile_code),
        symbols={},
        added_functions=added_functions,
    )
    patcher.utils = make_utils(
        architecture=patcher.archinfo,
        allocation_manager=manager,
        compiler=patcher.compiler,
        image=patcher.image,
        added_functions=patcher.added_functions,
    )

    InsertFunctionPatch("helper", "void helper(void) {}").apply(as_patcherex(patcher))

    assert [size for size, _ in manager.requests] == [3, 7]
    assert len(manager.freed) == 1
    assert patcher.symbols["helper"] == 0x2000
    assert image.updates == [(0x200, b"C" * 7)]


def apply_addressed_c_function_patch():
    compile_calls = []
    trampoline_calls = []
    initial_sizes = []
    image = FakeImageBackend()

    def compile_code(code, base=0, **kwargs):
        compile_calls.append((code, base, kwargs))
        return b"C"

    def allocate_generated_code(initial_size, build, **_kwargs):
        initial_sizes.append(initial_size)
        block = MappedBlock(addr=0x3000, file_addr=0x300, size=1, is_free=False)
        return block, build(block.mem_addr)

    patcher = FakePatchContext(
        image=image,
        architecture=X86.model_copy(
            update={
                "save_context_asm": "<save>",
                "restore_context_asm": "<restore>",
                "call_asm": "call {dst}",
            }
        ),
        binary_analyzer=FakeBinaryAnalyzer(is_thumb=lambda addr: addr == 0x1000),
        compiler=FakeCompiler(compile_code),
        symbols={},
        added_functions=[],
        utils=FakePatchUtils(
            allocate_generated_code=allocate_generated_code,
            insert_trampoline_code=lambda *args, **kwargs: trampoline_calls.append((args, kwargs)),
        ),
    )
    patch = InsertFunctionPatch(
        0x1000,
        "void helper(void) {}",
        detour_pos=0x2000,
        symbols={"external": 0x4000},
        prefunc="SAVE_CONTEXT pre",
        postfunc="post RESTORE_CONTEXT",
        save_context=True,
        compile_opts={"extra_compiler_flags": ["-Os"]},
    )

    patch.apply(as_patcherex(patcher))

    return patcher, compile_calls, trampoline_calls, initial_sizes, image


def test_addressed_c_function_patch_builds_thumb_helper_at_final_address():
    patcher, compile_calls, _trampoline_calls, initial_sizes, image = (
        apply_addressed_c_function_patch()
    )

    assert [(base, kwargs["is_thumb"]) for _, base, kwargs in compile_calls] == [
        (0, True),
        (0x3000, True),
    ]
    assert initial_sizes == [1]
    assert patcher.symbols["__patcherex_0x1000"] == 0x3001
    assert image.updates == [(0x300, b"C")]


def test_addressed_function_forwards_compiler_options_to_its_helper():
    _, calls, _, _, _ = apply_addressed_c_function_patch()
    assert calls
    assert all(kwargs["extra_compiler_flags"] == ["-Os"] for _, _, kwargs in calls)


def test_addressed_c_function_patch_builds_context_preserving_trampoline():
    _patcher, _compile_calls, trampoline_calls, _initial_sizes, _image = (
        apply_addressed_c_function_patch()
    )

    assert len(trampoline_calls) == 1
    trampoline_args, trampoline_kwargs = trampoline_calls[0]
    source_addr, trampoline = trampoline_args
    assert source_addr == 0x1000
    assert trampoline.count("<save>") == 2
    assert trampoline.count("<restore>") == 2
    call = "call <__patcherex_0x1000>"
    assert call in trampoline
    assert trampoline.index("<save>") < trampoline.index("pre")
    assert trampoline.index("pre") < trampoline.index(call)
    assert trampoline.index(call) < trampoline.index("post")
    assert trampoline.index("post") < trampoline.index("<restore>")
    assert trampoline_kwargs == {
        "force_insert": False,
        "detour_pos": 0x2000,
        "symbols": {"external": 0x4000},
    }


def test_modify_function_recompiles_until_final_address_bytes_fit():
    manager = make_resizing_allocator()
    image = FakeImageBackend()

    def compile_code(_code, base=0, **_kwargs):
        return b"C" * (3 if base == 0x500 else 7)

    patcher = FakePatchContext(
        image=image,
        allocation_manager=manager,
        architecture=X86,
        assembler=make_assembler(lambda *_args, **_kwargs: b"J"),
        binary_analyzer=FakeBinaryAnalyzer(
            get_function=lambda _target: FunctionInfo(addr=0x500, size=2),
            is_thumb=lambda _addr: False,
            map_address=lambda addr: addr,
        ),
        compiler=FakeCompiler(compile_code),
    )
    patcher.utils = make_utils(
        architecture=patcher.archinfo,
        allocation_manager=manager,
        assembler=patcher.assembler,
        compiler=patcher.compiler,
        binary_analyzer=patcher.binary_analyzer,
        image=patcher.image,
    )

    ModifyFunctionPatch("target", "return 0;").apply(as_patcherex(patcher))

    assert [size for size, _ in manager.requests] == [3, 7]
    assert len(manager.freed) == 1
    assert image.updates == [(0x200, b"C" * 7), (0x500, b"J")]


def test_explicit_named_asm_detour_is_a_memory_address():
    image = FakeImageBackend()
    analyzer = FakeBinaryAnalyzer(map_address=lambda addr: addr - 0x400000)
    patcher = FakePatchContext(
        image=image,
        architecture=X86,
        assembler=make_assembler(lambda *_args, **_kwargs: b"A", analyzer),
        binary_analyzer=analyzer,
        symbols={},
    )
    patcher.utils = make_utils(
        architecture=patcher.archinfo,
        assembler=patcher.assembler,
        binary_analyzer=patcher.binary_analyzer,
        image=patcher.image,
    )

    InsertInstructionPatch("helper", "nop", detour_pos=0x401234).apply(as_patcherex(patcher))

    assert patcher.symbols["helper"] == 0x401234
    assert image.updates == [(0x1234, b"A")]
