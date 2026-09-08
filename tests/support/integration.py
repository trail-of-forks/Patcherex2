from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from errno import ENOEXEC
from pathlib import Path

import pytest

from patcherex2 import ComponentSelections, PatchSession, TargetConfig
from patcherex2.patch import Patch
from patcherex2.targets import TargetDefinition


class IntegrationTestMixin:
    """Run patch cases against a target binary and verify observable behavior."""

    bin_location: str
    binary_analyzer: str
    target: TargetDefinition

    def run_one(
        self,
        filename: str,
        patches: Iterable[Patch],
        inputvalue: bytes | None = None,
        expected_output: bytes | None = None,
        expected_return_code: int | None = None,
        config: TargetConfig | None = None,
    ) -> None:
        filepath = Path(self.bin_location) / filename
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "patched"
            with PatchSession.load_binary(
                filepath,
                target=self.target,
                config=config
                or TargetConfig(
                    selections=ComponentSelections(binary_analyzer=self.binary_analyzer),
                ),
            ) as patcher:
                patcher.patches.extend(patches)
                patcher.apply_patches()
                patcher.save_binary(str(output_path))

            try:
                result = subprocess.run(
                    [output_path],
                    input=inputvalue,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                pytest.fail(
                    "patched binary did not exit within 30s, "
                    f"binary dumped: {self._preserve_failed_binary(output_path)}"
                )
            except OSError as error:
                if error.errno != ENOEXEC:
                    raise
                pytest.skip(f"cannot execute target binary on this host: {error}")

            if expected_output is not None and result.stdout != expected_output:
                pytest.fail(
                    f"{result.stdout!r} != {expected_output!r}, "
                    f"binary dumped: {self._preserve_failed_binary(output_path)}"
                )
            if expected_return_code is not None and result.returncode != expected_return_code:
                pytest.fail(
                    f"{result.returncode} != {expected_return_code}, "
                    f"binary dumped: {self._preserve_failed_binary(output_path)}"
                )

    @staticmethod
    def _preserve_failed_binary(source: Path) -> Path:
        failure_dir = Path(tempfile.mkdtemp(prefix="patcherex2-failure-"))
        destination = failure_dir / source.name
        shutil.copyfile(source, destination)
        return destination
