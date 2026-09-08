from __future__ import annotations

import abc
import sys
from collections.abc import Mapping
from typing import Any, Protocol, final, runtime_checkable

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


@runtime_checkable
class Compiler(Protocol):
    """Anything capable of compiling source into image-ready bytes."""

    preserve_none: bool

    @abc.abstractmethod
    def compile(
        self,
        code: str,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        is_thumb: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """Compile source code into bytes suitable for insertion into an image."""
        raise NotImplementedError()


@runtime_checkable
class ObjectCompiler(Protocol):
    """Anything capable of compiling source into an intermediate object."""

    preserve_none: bool

    @abc.abstractmethod
    def compile_object(
        self,
        code: str,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Compile source into an object understood by a compilation engine."""
        raise NotImplementedError()


@runtime_checkable
class CompilationEngine(Protocol):
    """Anything capable of converting an object into image-ready bytes."""

    @abc.abstractmethod
    def compile(
        self,
        object_bytes: bytes,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
    ) -> bytes:
        """Resolve and convert an intermediate object into final patch bytes."""
        raise NotImplementedError()


@final
class CompilerPipeline(Compiler):
    """Compose an object compiler with a format-specific compilation engine."""

    def __init__(
        self,
        object_compiler: ObjectCompiler,
        compilation_engine: CompilationEngine,
    ) -> None:
        self.object_compiler: ObjectCompiler = object_compiler
        self.compilation_engine: CompilationEngine = compilation_engine
        self.preserve_none = object_compiler.preserve_none

    @override
    def compile(
        self,
        code: str,
        base: int = 0,
        symbols: Mapping[str, int] | None = None,
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        is_thumb: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """Compile source and pass its object to the configured engine."""
        del is_thumb
        object_bytes = self.object_compiler.compile_object(
            code,
            extension=extension,
            extra_compiler_flags=extra_compiler_flags,
            **kwargs,
        )
        return self.compilation_engine.compile(
            object_bytes,
            base=base,
            symbols=symbols,
        )
