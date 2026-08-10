#!/usr/bin/env python

"""
Regression tests for symbol placeholder syntax in patch assembly.

Symbols used to be referenced as ``{name}``, which collides with ARM register
list syntax: ``push {r7}`` and ``push {lr}`` are valid assembly, and the
substitution was a blind ``str.replace`` over every known symbol. A target with
a symbol named ``r7`` therefore rewrote the user's instruction. ``<name>`` has
no such conflict, and these tests pin both the fixed behaviour and the original
failure mode.
"""

import warnings

import pytest

from patcherex2.components.assemblers.assembler import (
    Assembler,
    UnresolvedSymbolError,
)
from patcherex2.components.binary_analyzers.symbol import MappedSymbol

keystone = pytest.importorskip("keystone", reason="keystone-engine not available")


#: Addresses chosen so a substituted value is obviously not a register.
SYMBOLS = {
    "return_0x32": 0x400100,
    "added_data": 0x404100,
    # The collision: names that are also ARM registers.
    "lr": 0x405000,
    "r7": 0x406000,
}


class _FakeBinaryAnalyzer:
    def get_all_symbols(self):
        return {name: MappedSymbol(name, addr) for name, addr in SYMBOLS.items()}


class _FakePatcherex:
    symbols: dict = {}

    def __init__(self):
        self.binary_analyzer = _FakeBinaryAnalyzer()


@pytest.fixture
def assembler():
    return Assembler(_FakePatcherex())


@pytest.fixture
def ks_arm():
    return keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)


def legacy_resolve(code, symbols):
    """The original substitution, reproduced to pin what it did wrong."""
    for symbol, addr in symbols.items():
        code = code.replace(f"{{{symbol}}}", hex(addr))
    return code


# --------------------------------------------------------------------------
# The original failure mode.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("code", ["push {lr}", "push {r7}"])
def test_legacy_syntax_corrupted_register_lists(code, ks_arm):
    """
    A single-register list was rewritten into a bare address by the old
    substitution, because the register name also named a symbol.

    The result does not assemble, so the failure was loud rather than silent --
    but it fired on assembly the user wrote correctly, and no spelling of the
    instruction could avoid it while the symbol existed.
    """
    mangled = legacy_resolve(code, SYMBOLS)
    assert mangled != code, "expected the old substitution to rewrite the reglist"
    assert mangled.startswith("push 0x")
    with pytest.raises(keystone.KsError):
        ks_arm.asm(mangled)


@pytest.mark.parametrize("code", ["push {lr}", "push {r7}", "push {r0-r11}"])
def test_register_lists_survive_resolution(assembler, ks_arm, code):
    """Register lists must reach the assembler untouched, symbols notwithstanding."""
    assert assembler.resolve_symbols(code) == code
    assert bytes(ks_arm.asm(code)[0])


# --------------------------------------------------------------------------
# The silent case: a reference that resolves, but to the wrong address.
# --------------------------------------------------------------------------


#: Where the patch author believes their symbol lives, versus what the target's
#: own symbol table says for the same (register-shaped) name.
INTENDED_LR = 0x400100


def test_legacy_syntax_branched_to_a_shadowing_symbol(ks_arm):
    """
    The silent failure: ``b {lr}`` assembles whichever address it resolves to.

    A patch author writing ``b {lr}`` means the symbol they know as ``lr``. If
    the target also has a symbol of that name at a different address -- and
    ``lr`` is an ordinary C identifier, so it can -- the analyzer's entry wins
    and the branch goes somewhere else. Unlike ``push {lr}``, which becomes
    invalid assembly and faults, a branch target accepts any address, so nothing
    rejects it and the patched binary is simply wrong.
    """
    shadowed = legacy_resolve("b {lr}", SYMBOLS)
    intended = legacy_resolve("b {lr}", {"lr": INTENDED_LR})

    # The user's own spelling is nowhere in either result: it resolved silently.
    assert "{lr}" not in shadowed
    assert shadowed == f"b {hex(SYMBOLS['lr'])}"

    shadowed_enc = bytes(ks_arm.asm(shadowed, addr=0x1000)[0])
    intended_enc = bytes(ks_arm.asm(intended, addr=0x1000)[0])

    # Both are well-formed 4-byte branches -- the assembler cannot tell them
    # apart, which is exactly what made this silent rather than a hard error.
    assert len(shadowed_enc) == len(intended_enc) == 4
    assert shadowed_enc != intended_enc


def test_angle_brackets_branch_to_the_named_symbol(assembler, ks_arm):
    """
    The same reference under ``<name>`` resolves to the symbol that was named.

    This does not remove the shadowing itself -- a target symbol named ``lr``
    still wins over an identically named one the author had in mind -- but the
    reference is now unambiguous rather than colliding with register syntax,
    and an explicit ``symbols=`` entry can override it.
    """
    resolved = assembler.resolve_symbols("b <lr>")
    assert resolved == f"b {hex(SYMBOLS['lr'])}"
    assert len(bytes(ks_arm.asm(resolved, addr=0x1000)[0])) == 4

    overridden = assembler.resolve_symbols("b <lr>", symbols={"lr": INTENDED_LR})
    assert overridden == f"b {hex(INTENDED_LR)}"


def test_legacy_register_shaped_reference_is_left_for_the_assembler(assembler):
    """
    The legacy guard suppresses a substitution the author may have wanted.

    ``{r7}`` is assumed to be a register list so that ``push {r7}`` keeps
    working, which means a genuine symbol named ``r7`` goes unsubstituted. Here
    that surfaces as an assembler error rather than a wrong address, but it is
    a real limitation of the brace syntax and the reason it is deprecated --
    ``<r7>`` has no such ambiguity.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert assembler.resolve_symbols("b {r7}") == "b {r7}"

    assert assembler.resolve_symbols("b <r7>") == f"b {hex(SYMBOLS['r7'])}"


# --------------------------------------------------------------------------
# The replacement syntax.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected",
    [
        ("b <return_0x32>", "b 0x400100"),
        ("ldr r1, =<added_data>", "ldr r1, =0x404100"),
        ("lea rsi, [<added_data>]", "lea rsi, [0x404100]"),
    ],
)
def test_angle_brackets_resolve(assembler, code, expected):
    assert assembler.resolve_symbols(code) == expected


def test_angle_brackets_and_register_list_together(assembler, ks_arm):
    """A register list and a symbol reference in the same instruction stream."""
    code = "push {r0-r11}\nb <return_0x32>"
    resolved = assembler.resolve_symbols(code)
    assert "{r0-r11}" in resolved
    assert "0x400100" in resolved
    assert bytes(ks_arm.asm(resolved, addr=0x1000)[0])


def test_unresolved_symbol_raises(assembler):
    with pytest.raises(UnresolvedSymbolError, match="nonexistent_sym"):
        assembler.resolve_symbols("b <nonexistent_sym>")


def test_unresolved_symbol_names_every_missing_symbol(assembler):
    with pytest.raises(UnresolvedSymbolError) as excinfo:
        assembler.resolve_symbols("b <missing_a>\nb <missing_b>")
    assert "missing_a" in str(excinfo.value)
    assert "missing_b" in str(excinfo.value)


def test_caller_symbols_take_priority(assembler):
    resolved = assembler.resolve_symbols(
        "b <return_0x32>", symbols={"return_0x32": 0x1234}
    )
    assert resolved == "b 0x1234"


# --------------------------------------------------------------------------
# Deprecation of the legacy syntax.
# --------------------------------------------------------------------------


def test_legacy_syntax_still_works_but_warns(assembler):
    with pytest.warns(DeprecationWarning, match="deprecated"):
        resolved = assembler.resolve_symbols("b {return_0x32}")
    assert resolved == "b 0x400100"


def test_legacy_register_shaped_name_is_not_substituted(assembler):
    """``push {r7}`` stays assembly even though ``r7`` names a symbol."""
    with warnings.catch_warnings():
        # A deprecation warning here would mean it was treated as a reference.
        warnings.simplefilter("error", DeprecationWarning)
        assert assembler.resolve_symbols("push {r7}") == "push {r7}"


def test_legacy_register_shaped_name_honours_explicit_override(assembler):
    """An explicitly passed symbol is deliberate, so it wins over the register."""
    with pytest.warns(DeprecationWarning):
        resolved = assembler.resolve_symbols("push {r7}", symbols={"r7": 0x1234})
    assert resolved == "push 0x1234"
