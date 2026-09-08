import logging
import re
import sys
from typing import final

import keystone

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler.keystone import KeystoneAssemblyBackend

logger = logging.getLogger(__name__)


@final
class KeystoneSparcAssemblyBackend(KeystoneAssemblyBackend):
    """Correct Keystone's SPARC PC-relative branch preprocessing."""

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        code = self._rewrite_pc_relative_branches(code, base)
        return super().assemble(code, base, is_thumb=is_thumb)

    def _rewrite_pc_relative_branches(self, code: str, base: int) -> str:
        # SPARC branches jump to PC + 4 * immediate, while Keystone interprets
        # their operand inconsistently. Convert absolute patch targets first.
        if self.arch != keystone.KS_ARCH_SPARC:
            return code
        result = ""
        lineno = 0
        for line in code.splitlines():
            line = line.strip()
            if line.startswith((".", "#")) or line == "" or line.endswith(":"):
                result += line + "\n"
                continue
            if re.match(r"(call|b|ba) 0x[0-9a-fA-F]+", line):
                instr, addr = line.split(" ")
                addr = int(addr, 16)
                disp = addr - base
                imm = disp >> 2
                logger.debug(f"converting {line} to {instr} {hex(imm)} (base: {hex(base)})")
                if instr == "call":
                    result += f"{instr} {hex(base + imm - lineno)}\n"
                elif instr == "b" or instr == "ba":
                    result += f"{instr} {hex(addr - (4 * lineno))}\n"
            else:
                result += line + "\n"
            lineno += 1
        return result
