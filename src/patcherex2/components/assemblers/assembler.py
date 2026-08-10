import logging
import re
import warnings

logger = logging.getLogger(__name__)

#: A ``<name>`` symbol placeholder in patch assembly. Angle brackets are unused
#: by every assembler syntax patcherex2 targets, so a match here is always a
#: symbol reference and never something the user meant literally.
SYMBOL_PLACEHOLDER_RE = re.compile(r"<([A-Za-z_.$][A-Za-z0-9_.$]*)>")

#: The legacy ``{name}`` placeholder, deprecated in favour of ``<name>``.
#:
#: Braces collide with ARM register-list syntax: ``push {r0-r11}`` and
#: ``push {r7}`` are valid assembly, and a binary with a symbol named ``r7``
#: would have had that instruction silently rewritten into ``push 0x...``.
#: Multi-register lists are excluded by requiring a symbol-shaped name (they
#: contain ``-`` or ``,``), but a single-register list is indistinguishable from
#: a placeholder, which is why this form cannot be made safe and is going away.
LEGACY_SYMBOL_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_.$][A-Za-z0-9_.$]*)\}")

#: Register names a single-register list could produce, used only to keep the
#: deprecated ``{name}`` form from corrupting valid ARM assembly. Not needed for
#: ``<name>``, which cannot collide with a register list at all.
REGISTER_NAME_RE = re.compile(
    r"^(?:[rdqsvxwfa]\d+|xmm\d+|ymm\d+|zmm\d+|"
    r"lr|sp|fp|ip|pc|sl|sb|[er]?(?:ax|bx|cx|dx|si|di|bp|sp)|"
    r"[at]\d+|s\d+|k\d+|cr\d+|f\d+)$",
    re.IGNORECASE,
)


class UnresolvedSymbolError(Exception):
    """
    Raised when patch assembly references a ``<symbol>`` that has no address.

    :meth:`Assembler.resolve_symbols` replaces ``<name>`` with the symbol's
    address. A name that matches nothing was previously left in the assembly
    verbatim, where it either produced a confusing assembler error or, worse,
    assembled as something unintended. Reporting it here names the symbol the
    patch actually asked for.
    """


class Assembler:
    def __init__(self, p) -> None:
        self.p = p

    def resolve_symbols(self, code: str, symbols=None):
        """
        Replace ``<symbol>`` placeholders in ``code`` with symbol addresses.

        Addresses come from, in increasing priority: the analyzer's view of the
        target, :attr:`Patcherex.symbols`, and ``symbols``.

        The legacy ``{symbol}`` form is still honoured but deprecated; see
        :data:`LEGACY_SYMBOL_PLACEHOLDER_RE` for why it is unsafe on ARM.

        :raises UnresolvedSymbolError: If a placeholder has no known address.
        """
        if symbols is None:
            symbols = {}
        if not hasattr(self, "_binary_symbols_cache"):
            self._binary_symbols_cache = {
                name: symbol.addr
                for name, symbol in self.p.binary_analyzer.get_all_symbols().items()
            }
        _symbols = {}
        _symbols.update(self.p.symbols)
        _symbols.update(self._binary_symbols_cache)
        _symbols.update(symbols)

        # Collected before substituting so that a substituted address whose text
        # happens to look like a placeholder cannot be mistaken for one.
        requested = set(SYMBOL_PLACEHOLDER_RE.findall(code))
        legacy = set(LEGACY_SYMBOL_PLACEHOLDER_RE.findall(code))
        # A name that is only register-shaped is assembly (`push {r7}`), not a
        # reference, unless the caller named it explicitly in symbols=.
        legacy = {
            name
            for name in legacy
            if name in symbols or not REGISTER_NAME_RE.match(name)
        }
        if legacy:
            warnings.warn(
                f"Referencing symbols as {{{sorted(legacy)[0]}}} is deprecated and "
                f"will be removed; write <{sorted(legacy)[0]}> instead. Braces are "
                f"ambiguous with ARM register lists such as `push {{r7}}`.",
                DeprecationWarning,
                stacklevel=3,
            )

        for symbol, addr in _symbols.items():
            code = code.replace(f"<{symbol}>", hex(addr))
            if symbol in legacy:
                code = code.replace(f"{{{symbol}}}", hex(addr))

        unresolved = sorted((requested | legacy) - set(_symbols))
        if unresolved:
            raise UnresolvedSymbolError(
                f"Patch assembly references {', '.join('<' + n + '>' for n in unresolved)}, "
                f"which the binary analyzer did not report and which was not passed "
                f"in symbols=. Check the spelling, or pass the address explicitly, "
                f"e.g. symbols={{'{unresolved[0]}': 0x...}}."
            )
        return code

    def _assemble(self, code: str, base=0, **kwargs) -> None:
        raise NotImplementedError()

    def _pre_assemble_hook(self, code: str, base=0) -> None:
        return code

    def assemble(self, code: str, base=0, symbols=None, **kwargs) -> None:
        if code == "":
            return b""
        if symbols is None:
            symbols = {}
        logger.debug(f"Assembling `{code}` at {hex(base)}")
        code = self.resolve_symbols(code, symbols=symbols)
        code = self._pre_assemble_hook(code, base=base)

        return self._assemble(code, base=base, **kwargs)
