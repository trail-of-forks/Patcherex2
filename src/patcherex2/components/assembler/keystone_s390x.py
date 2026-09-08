import sys
from typing import final

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.assembler.keystone import KeystoneAssemblyBackend


@final
class S390xAssemblyBackend(KeystoneAssemblyBackend):
    """Adjust absolute S390x jumps for Keystone's addressing behavior."""

    @override
    def assemble(self, code: str, base: int = 0, *, is_thumb: bool = False) -> bytes:
        rounded_base = base - (base % 0x1000000)
        lines = []
        for line in code.splitlines():
            line = line.strip()
            if line.startswith("j 0x"):
                destination = int(line.split(" ")[1], 16) - rounded_base
                line = f"j {hex(destination)}"
            lines.append(line)
        return super().assemble("\n".join(lines), base, is_thumb=is_thumb)
