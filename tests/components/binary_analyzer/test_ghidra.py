# ruff: noqa: N802
from contextlib import contextmanager

import pytest

from patcherex2.components.binary_analyzer import (
    UnknownInstructionModeError,
)
from patcherex2.components.binary_analyzer.ghidra import GhidraAnalysis, GhidraAnalyzer


def test_load_binary_uses_injected_api_for_analysis_lifetime():
    events = []
    monitor = object()
    consumer = object()

    class Program:
        def release(self, consumer):
            events.append(("release", consumer))

        def getImageBase(self):
            raise AssertionError("not used by lifecycle test")

        def getRelocationTable(self):
            raise AssertionError("not used by lifecycle test")

        def getMemory(self):
            raise AssertionError("not used by lifecycle test")

        def getListing(self):
            raise AssertionError("not used by lifecycle test")

        def getSymbolTable(self):
            raise AssertionError("not used by lifecycle test")

        def getRegister(self, name):
            raise AssertionError(f"register {name} is not used by lifecycle test")

        def getProgramContext(self):
            raise AssertionError("not used by lifecycle test")

    program = Program()

    class FakeFlatProgramApi:
        def toAddr(self, value):
            return FakeAddress(int(value, 0))

    class FakeLifecycleBlockModel:
        def getFirstCodeBlockContaining(self, address, selected_monitor):
            raise AssertionError(f"block lookup at {address} with {selected_monitor} is not used")

    class FakeGhidraApi:
        @contextmanager
        def load_binary(self, binary_path, language):
            events.append(("load", binary_path, language))
            events.append("load enter")
            try:
                yield GhidraAnalysis(
                    program=program,
                    flat_program_api=FakeFlatProgramApi(),
                    basic_block_model=FakeLifecycleBlockModel(),
                    task_monitor=monitor,
                )
            finally:
                program.release(consumer)
                events.append("load exit")

    with GhidraAnalyzer.load_binary(
        "firmware.elf",
        "ARM:LE:32:v8",
        api=FakeGhidraApi(),
    ) as analyzer:
        assert analyzer.program is program
        assert isinstance(analyzer.flat_program_api, FakeFlatProgramApi)
        assert isinstance(analyzer.basic_block_model, FakeLifecycleBlockModel)
        assert analyzer.task_monitor is monitor

    assert events == [
        ("load", "firmware.elf", "ARM:LE:32:v8"),
        "load enter",
        ("release", consumer),
        "load exit",
    ]


class FakeAddress:
    def __init__(self, offset: int) -> None:
        self.offset = offset

    def getOffset(self) -> int:
        return self.offset


class FakeFlatApi:
    def toAddr(self, value: str) -> FakeAddress:
        return FakeAddress(int(value, 0))


class FakeRegisterValue:
    def __init__(self, value: int | None) -> None:
        self.value = value
        self.unsignedValueIgnoreMask = FakeUnsignedValue(0 if value is None else value)

    def hasValue(self) -> bool:
        return self.value is not None


class FakeUnsignedValue:
    def __init__(self, value: int) -> None:
        self.value = value

    def intValue(self) -> int:
        return self.value


class FakeRelocationTable:
    def __init__(self, relocatable: bool) -> None:
        self.relocatable = relocatable

    def isRelocatable(self) -> bool:
        return self.relocatable


class FakeRegister:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeProgramContext:
    def __init__(self, register_value: int | None) -> None:
        self.register_value = register_value

    def getRegisterValue(self, _register, _address) -> FakeRegisterValue:
        return FakeRegisterValue(self.register_value)


class FakeBasicBlockModel:
    def getFirstCodeBlockContaining(self, address, monitor):
        raise AssertionError(f"block lookup at {address} with {monitor} was unexpected")


class FakeTaskMonitor:
    pass


class FakeProgram:
    def __init__(
        self,
        register_value: int | None,
        relocatable: bool = True,
        *,
        has_tmode_register: bool = True,
    ) -> None:
        self._register_value = register_value
        self._relocatable = relocatable
        self._has_tmode_register = has_tmode_register

    def getImageBase(self) -> FakeAddress:
        return FakeAddress(0x1000)

    def getRelocationTable(self) -> FakeRelocationTable:
        return FakeRelocationTable(self._relocatable)

    def getRegister(self, name: str) -> FakeRegister | None:
        if not self._has_tmode_register:
            return None
        return FakeRegister(name)

    def getProgramContext(self) -> FakeProgramContext:
        return FakeProgramContext(self._register_value)

    def getMemory(self):
        raise AssertionError("memory API was not configured")

    def getListing(self):
        raise AssertionError("listing API was not configured")

    def getSymbolTable(self):
        raise AssertionError("symbol API was not configured")

    def release(self, consumer):
        raise AssertionError(f"unexpected release by {consumer}")


def make_analyzer(
    register_value: int | None,
    relocatable: bool = True,
    *,
    has_tmode_register: bool = True,
) -> GhidraAnalyzer:
    return GhidraAnalyzer(
        FakeProgram(register_value, relocatable, has_tmode_register=has_tmode_register),
        FakeFlatApi(),
        FakeBasicBlockModel(),
        FakeTaskMonitor(),
    )


def test_relocatable_addresses_are_normalized_relative_to_image_base():
    analyzer = make_analyzer(register_value=1)

    assert analyzer.normalize_addr(0x1234) == 0x234
    assert analyzer.denormalize_addr(0x234) == 0x1234


def test_integer_address_is_converted_at_ghidra_api_boundary():
    analyzer = make_analyzer(register_value=1)

    assert analyzer._to_ghidra_addr(0x234).getOffset() == 0x1234


@pytest.mark.parametrize(("register_value", "expected"), [(1, True), (0, False)])
def test_thumb_mode_returns_known_register_value(register_value, expected):
    assert make_analyzer(register_value).thumb_mode(0x234) is expected


def test_thumb_mode_returns_none_for_missing_register_value():
    assert make_analyzer(None).thumb_mode(0x234) is None


def test_is_thumb_rejects_missing_register_value():
    analyzer = make_analyzer(None)

    with pytest.raises(UnknownInstructionModeError):
        analyzer.is_thumb(0x234)


def test_missing_tmode_register_is_definitely_arm():
    analyzer = make_analyzer(1, has_tmode_register=False)

    assert analyzer.thumb_mode(0x234) is False
