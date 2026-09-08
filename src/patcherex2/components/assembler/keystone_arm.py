import logging
import sys
from typing import Any, SupportsBytes, cast, final

import keystone

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import AssemblyBackend

logger = logging.getLogger(__name__)


@final
class KeystoneArmAssemblyBackend(AssemblyBackend):
    """Assemble ARM and Thumb code with dedicated Keystone instances."""

    def __init__(self) -> None:
        self.ks_arm: keystone.Ks = keystone.Ks(
            keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN
        )
        self.ks_thumb: keystone.Ks = keystone.Ks(
            keystone.KS_ARCH_ARM,
            keystone.KS_MODE_THUMB + keystone.KS_MODE_LITTLE_ENDIAN,
        )

    @override
    def assemble(
        self,
        code: str,
        base: int = 0,
        *,
        is_thumb: bool = False,
    ) -> bytes:
        try:
            ks = self.ks_thumb if is_thumb else self.ks_arm
            cast(SupportsBytes, bytes(12))
            binary, _ = cast(tuple[SupportsBytes, Any], ks.asm(code, base))
            logger.debug(f"Assembled bytes: {bytes(binary).hex()}")
            return bytes(binary)
        except Exception as error:
            raise ValueError(
                f'Failed to assemble: """\n{code}\n"""\nat base: {hex(base)}'
            ) from error
