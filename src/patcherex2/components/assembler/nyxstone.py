import logging
import sys
from typing import final

import nyxstone

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler import AssemblyBackend

logger = logging.getLogger(__name__)


@final
class NyxstoneAssemblyBackend(AssemblyBackend):
    """Assemble code through Nyxstone for a configured LLVM target."""

    def __init__(
        self,
        target_triple: str,
        cpu: str = "",
        features: str = "",
    ) -> None:
        self.target_triple: str = target_triple
        self.cpu: str = cpu
        self.features: str = features
        self.ns = nyxstone.Nyxstone(target_triple, cpu, features)

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        if is_thumb:
            raise ValueError("Nyxstone assembly does not support Thumb mode")
        symbols = {}
        if self.target_triple == "riscv32":
            for line in code.splitlines():
                line = line.strip()
                if line.startswith(("j ", "jal ", "call ", "tail ")):
                    parts = line.split(" ")
                    if len(parts) == 2 and not parts[1].startswith("__patcherex_"):
                        addr = int(parts[1], 0)
                        code = code.replace(line, f"{parts[0]} __patcherex_{hex(addr)}")
                        symbols[f"__patcherex_{hex(addr)}"] = addr
        try:
            binary = self.ns.assemble(code, base, symbols)
            logger.debug(f"Assembled bytes: {bytes(binary).hex()}")
            return bytes(binary)
        except Exception as error:
            raise ValueError(
                f'Failed to assemble: """\n{code}\n"""\nat base: {hex(base)}'
            ) from error
