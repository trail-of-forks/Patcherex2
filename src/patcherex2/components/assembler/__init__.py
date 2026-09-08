from __future__ import annotations

import abc
import logging
import re
import warnings
from collections.abc import Mapping
from typing import Protocol, final

from patcherex2.components.symbol_resolver import SymbolResolver

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


class AssemblyBackend(Protocol):
    """Architecture-specific machine-code assembly."""

    @abc.abstractmethod
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        """Assemble resolved source into machine code at ``base``."""
        raise NotImplementedError()


@final
class Assembler:
    """Resolve patch symbols before delegating to an assembly backend."""

    def __init__(self, symbol_resolver: SymbolResolver, backend: AssemblyBackend) -> None:
        self.symbol_resolver: SymbolResolver = symbol_resolver
        self.backend: AssemblyBackend = backend

    def resolve_symbols(self, code: str, symbols: Mapping[str, int] | None = None) -> str:
        """
        Replace ``<symbol>`` placeholders in ``code`` with symbol addresses.

        Addresses come from, in increasing priority: the analyzer's view of the
        target, :attr:`PatchSession.symbols`, and ``symbols``.

        The legacy ``{symbol}`` form is still honoured but deprecated; see
        :data:`LEGACY_SYMBOL_PLACEHOLDER_RE` for why it is unsafe on ARM.

        :raises UnresolvedSymbolError: If a placeholder has no known address.
        """
        if symbols is None:
            symbols = {}
        resolved_symbols = self.symbol_resolver.resolve(symbols)

        # Collected before substituting so that a substituted address whose text
        # happens to look like a placeholder cannot be mistaken for one.
        requested = set(SYMBOL_PLACEHOLDER_RE.findall(code))
        legacy = set(LEGACY_SYMBOL_PLACEHOLDER_RE.findall(code))
        # A name that is only register-shaped is assembly (`push {r7}`), not a
        # reference, unless the caller named it explicitly in symbols=.
        legacy = {name for name in legacy if name in symbols or not REGISTER_NAME_RE.match(name)}
        if legacy:
            warnings.warn(
                f"Referencing symbols as {{{min(legacy)}}} is deprecated and "
                f"will be removed; write <{min(legacy)}> instead. Braces are "
                f"ambiguous with ARM register lists such as `push {{r7}}`.",
                DeprecationWarning,
                stacklevel=3,
            )

        for symbol, addr in resolved_symbols.items():
            code = code.replace(f"<{symbol}>", hex(addr))
            if symbol in legacy:
                code = code.replace(f"{{{symbol}}}", hex(addr))

        unresolved = sorted((requested | legacy) - set(resolved_symbols))
        if unresolved:
            raise UnresolvedSymbolError(
                f"Patch assembly references {', '.join('<' + n + '>' for n in unresolved)}, "
                f"which the binary analyzer did not report and which was not passed "
                f"in symbols=. Check the spelling, or pass the address explicitly, "
                f"e.g. symbols={{'{unresolved[0]}': 0x...}}."
            )
        return code

    def assemble(
        self,
        code: str,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
        *,
        is_thumb: bool = False,
    ) -> bytes:
        """Resolve symbols and assemble source at ``base``."""
        if code == "":
            return b""
        if symbols is None:
            symbols = {}
        logger.debug(f"Assembling `{code}` at {hex(base)}")
        code = self.resolve_symbols(code, symbols=symbols)
        return self.backend.assemble(code, base=base, is_thumb=is_thumb)
