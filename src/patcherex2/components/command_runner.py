from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import Protocol, final


class CommandRunner(Protocol):
    """Execute an external command and return its captured result."""

    def run(self, command: Sequence[str], /) -> subprocess.CompletedProcess[bytes]:
        """Execute ``command``, raising when it exits unsuccessfully."""
        ...


@final
class SubprocessCommandRunner:
    """Execute commands through the host subprocess implementation."""

    def run(self, command: Sequence[str], /) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(command, check=True, capture_output=True)


DEFAULT_COMMAND_RUNNER = SubprocessCommandRunner()
