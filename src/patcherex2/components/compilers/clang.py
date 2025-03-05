from __future__ import annotations

import logging

from .compiler import Compiler

logger = logging.getLogger(__name__)


class Clang(Compiler):
    def __init__(
        self, p, clang_version : str | None = None, compiler_flags: list[str] | None = None
    ) -> None:
        super().__init__(p)
        if clang_version:
            self.preserve_none = clang_version >= 19
            self._compiler = f"clang-{clang_version}"
            self._linker = f"ld.lld-{clang_version}"
        else:
            self._compiler = f"clang"
            self._linker = f"ld.lld"
        self._compiler_flags = compiler_flags or []
