import logging
import sys
from typing import Any, SupportsBytes, cast

import keystone

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import AssemblyBackend

logger = logging.getLogger(__name__)


class KeystoneAssemblyBackend(AssemblyBackend):
    """Assemble code through Keystone for a configured architecture and mode."""

    def __init__(self, arch: int, mode: int) -> None:
        self.arch: int = arch
        self.mode: int = mode
        self.ks: keystone.Ks = keystone.Ks(arch, mode)

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        if is_thumb:
            raise ValueError("This Keystone backend does not support Thumb mode")
        try:
            # Keystone uses semicolons as instruction separators, not newlines
            code = code.replace("\n", ";")
            binary, _ = cast(tuple[SupportsBytes, Any], self.ks.asm(code, base))
            logger.debug(f"Assembled bytes: {bytes(binary).hex()}")
            return bytes(binary)
        except Exception as error:
            raise ValueError(
                f'Failed to assemble: """\n{code}\n"""\nat base: {hex(base)}'
            ) from error
