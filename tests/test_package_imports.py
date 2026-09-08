import subprocess
import sys
import textwrap

import pytest


def run_without_nyxstone(code: str) -> None:
    """Exercise imports in a fresh interpreter without the optional dependency."""
    blocker = """
import importlib.abc
import sys

class MissingNyxstone(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "nyxstone" or fullname.startswith("nyxstone."):
            raise ModuleNotFoundError("No module named 'nyxstone'", name="nyxstone")

sys.meta_path.insert(0, MissingNyxstone())
"""
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(blocker) + textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_package_import_does_not_require_nyxstone():
    run_without_nyxstone("""
import patcherex2
from patcherex2.components.assets import DEFAULT_ASSET_RESOLVER, AssetResolver
from patcherex2.targets.profiles import AMD64

assert callable(DEFAULT_ASSET_RESOLVER.resolve)
assert "nyxstone" not in sys.modules
""")


@pytest.mark.parametrize(
    ("module", "backend"),
    [
        ("patcherex2.components.assembler.nyxstone", "NyxstoneAssemblyBackend"),
        ("patcherex2.components.disassemblers.nyxstone", "Nyxstone"),
    ],
)
def test_missing_nyxstone_backend_explains_installation(module: str, backend: str):
    run_without_nyxstone(f"""
from {module} import {backend}

try:
    {backend}("riscv32")
except ModuleNotFoundError as error:
    assert error.name == "nyxstone"
    assert "patcherex2[nyxstone]" in str(error)
else:
    raise AssertionError("Constructing the backend must require Nyxstone")
""")
