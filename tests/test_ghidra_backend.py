# ruff: noqa: N802
from types import SimpleNamespace

import pytest

from patcherex2.components.binary_analyzers.binary_analyzer import (
    UnknownInstructionModeError,
)
from patcherex2.components.binary_analyzers.ghidra import Ghidra


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
        self.unsignedValueIgnoreMask = SimpleNamespace(
            intValue=lambda: 0 if value is None else value
        )

    def hasValue(self) -> bool:
        return self.value is not None


class FakeProgram:
    def __init__(self, register_value: int | None, relocatable: bool = True):
        self._register_value = register_value
        self._relocatable = relocatable

    def getImageBase(self) -> FakeAddress:
        return FakeAddress(0x1000)

    def getRelocationTable(self):
        return SimpleNamespace(isRelocatable=lambda: self._relocatable)

    def getRegister(self, name: str):
        return SimpleNamespace(name=name)

    def getProgramContext(self):
        return SimpleNamespace(
            getRegisterValue=lambda _register, _address: FakeRegisterValue(
                self._register_value
            )
        )


def make_analyzer(register_value: int | None, relocatable: bool = True) -> Ghidra:
    analyzer = Ghidra.__new__(Ghidra)
    analyzer.currentProgram = FakeProgram(register_value, relocatable)
    analyzer.flatapi = FakeFlatApi()
    return analyzer


def test_address_conversion_keeps_public_api_integer_based():
    analyzer = make_analyzer(register_value=1)

    assert analyzer.normalize_addr(0x1234) == 0x234
    assert analyzer.denormalize_addr(0x234) == 0x1234
    assert analyzer._to_ghidra_addr(0x234).getOffset() == 0x1234


def test_thumb_mode_returns_true_or_false_for_known_register_value():
    assert make_analyzer(1).thumb_mode(0x234) is True
    assert make_analyzer(0).thumb_mode(0x234) is False


def test_thumb_mode_returns_none_for_missing_register_value():
    analyzer = make_analyzer(None)

    assert analyzer.thumb_mode(0x234) is None
    with pytest.raises(UnknownInstructionModeError):
        analyzer.is_thumb(0x234)


def test_missing_tmode_register_is_definitely_arm():
    analyzer = make_analyzer(1)
    analyzer.currentProgram.getRegister = lambda _name: None

    assert analyzer.thumb_mode(0x234) is False
    assert analyzer.is_thumb(0x234) is False
