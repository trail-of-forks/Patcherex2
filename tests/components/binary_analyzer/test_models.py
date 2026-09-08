import pytest
from pydantic import ValidationError

from patcherex2.components.binary_analyzer import BasicBlock, FunctionInfo


def make_basic_block() -> BasicBlock:
    return BasicBlock(
        start=0x1000,
        size=8,
        instruction_addrs=(0x1000, 0x1004),
    )


def test_basic_block_end_is_derived_from_start_and_size():
    assert make_basic_block().end == 0x1008


def test_basic_block_serialization_does_not_duplicate_derived_end():
    block = make_basic_block()

    assert block.model_dump() == {
        "start": 0x1000,
        "size": 8,
        "instruction_addrs": (0x1000, 0x1004),
    }


def test_basic_block_rejects_an_independent_end():
    with pytest.raises(ValidationError, match="end"):
        BasicBlock.model_validate(
            {
                "start": 0x1000,
                "size": 8,
                "end": 0x2000,
                "instruction_addrs": (0x1000, 0x1004),
            }
        )


@pytest.mark.parametrize(
    "instruction_addrs",
    [
        (0x1004, 0x1000),
        (0x1000, 0x1000),
        (0x0FFF, 0x1000),
        (0x1000, 0x1008),
    ],
)
def test_basic_block_rejects_invalid_instruction_addresses(instruction_addrs):
    with pytest.raises(ValidationError):
        BasicBlock(start=0x1000, size=8, instruction_addrs=instruction_addrs)


@pytest.mark.parametrize(("addr", "size"), [(-1, 1), (0, -1)])
def test_function_info_rejects_negative_bounds(addr, size):
    with pytest.raises(ValidationError):
        FunctionInfo(addr=addr, size=size)
