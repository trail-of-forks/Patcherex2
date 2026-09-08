from __future__ import annotations

import abc
import logging
import sys
import traceback
from bisect import bisect_right
from collections.abc import Generator, Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Protocol, cast, final, runtime_checkable

import angr
from archinfo import ArchARM

from patcherex2.components.binary_analyzer import (
    BasicBlock,
    BinaryAnalyzer,
    FunctionInfo,
    UnknownInstructionModeError,
)

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from patcherex2.components.binary_analyzer.symbol import (
    ExternalSymbol,
    MappedSymbol,
    Symbol,
)

logger = logging.getLogger(__name__)


class AngrMainObjectApi(Protocol):
    @property
    def mapped_base(self) -> int: ...

    @property
    def pic(self) -> bool: ...

    @property
    def symbols(self) -> Iterable[Any]: ...

    @property
    def plt(self) -> Mapping[str, int]: ...

    def addr_to_offset(self, address: int) -> int | None: ...


class AngrLoaderApi(Protocol):
    @property
    def main_object(self) -> AngrMainObjectApi: ...


class AngrCfgModelApi(Protocol):
    def get_any_node(self, address: int, *, anyaddr: bool) -> Any: ...

    def nodes(self) -> Iterable[Any]: ...


class AngrCfgApi(Protocol):
    @property
    def model(self) -> AngrCfgModelApi: ...


class AngrProjectApi(Protocol):
    @property
    def arch(self) -> Any: ...

    @property
    def loader(self) -> AngrLoaderApi: ...

    @property
    def analyses(self) -> Any: ...

    @property
    def kb(self) -> Any: ...

    @property
    def factory(self) -> Any: ...


class AngrApi(Protocol):
    """Construct angr projects and their control-flow graphs."""

    def create_project(
        self,
        binary_path: str,
        options: Mapping[str, Any],
        /,
    ) -> AngrProjectApi: ...

    def create_cfg(
        self,
        project: AngrProjectApi,
        options: Mapping[str, Any],
        /,
    ) -> AngrCfgApi: ...


@final
class NativeAngrApi:
    """Adapt the installed angr package to the analyzer API."""

    def create_project(
        self,
        binary_path: str,
        options: Mapping[str, Any],
    ) -> AngrProjectApi:
        return cast(AngrProjectApi, angr.Project(binary_path, **options))

    def create_cfg(
        self,
        project: AngrProjectApi,
        options: Mapping[str, Any],
    ) -> AngrCfgApi:
        return cast(AngrCfgApi, project.analyses.CFGFast(**options))


DEFAULT_ANGR_API = NativeAngrApi()


@runtime_checkable
class CfgOptionsResolver(Protocol):
    """Callable object that resolves an Angr project API into CFG arguments."""

    @abc.abstractmethod
    def __call__(self, api: AngrProjectApi) -> Mapping[str, Any]:
        raise NotImplementedError()


@final
class AngrAnalyzer(BinaryAnalyzer):
    """Analyze a loaded project using an already-built control-flow graph.

    Use ``load_binary`` to build both, optionally resolving CFG options from the
    loaded project. Construct directly to use an existing project and CFG. CFG creation
    is eager: instances do not expose a mutable ``angr_cfg_kwargs`` attribute.
    """

    def __init__(
        self,
        project: AngrProjectApi,
        cfg: AngrCfgApi,
    ) -> None:
        self.project = project
        self.cfg = cfg
        self._load_base = None
        self._mapping_symbols = None

    @classmethod
    @contextmanager
    def load_binary(
        cls,
        binary_path: str,
        angr_kwargs: Mapping[str, Any] | None = None,
        angr_cfg_kwargs: Mapping[str, Any] | CfgOptionsResolver | None = None,
        *,
        api: AngrApi = DEFAULT_ANGR_API,
    ) -> Generator[AngrAnalyzer]:
        """Load a project and build its CFG before yielding the analyzer.

        Args:
            binary_path: Path to the binary to analyze.
            angr_kwargs: Project construction options, copied before use.
            angr_cfg_kwargs: CFG construction options or a callback returning
                them from the loaded project. The callback runs once, before CFG
                construction; exceptions propagate without building a CFG.
                Options are copied and normalization defaults to True. Regions
                and function starts must use the project's loaded address space.
            api: Adapter used to construct the project and CFG.

        Yields:
            An analyzer with its CFG already built. Changing the input option
            mappings afterward does not rebuild or rescope that CFG.
        """
        project_options = dict(angr_kwargs or {})
        project_options.setdefault("load_options", {"auto_load_libs": False})
        logger.info("Loading binary with angr")
        project = api.create_project(binary_path, project_options)
        logger.info("Loaded binary with angr")
        options = angr_cfg_kwargs(project) if isinstance(angr_cfg_kwargs, CfgOptionsResolver) else angr_cfg_kwargs
        cfg_options = dict(options or {})
        # Splitting blocks at incoming branches makes block boundaries useful
        # for instruction insertion.
        cfg_options.setdefault("normalize", True)

        logger.info("Generating CFG with angr")
        cfg = api.create_cfg(project, cfg_options)
        logger.info("Generated CFG with angr")
        yield cls(project, cfg)

    @property
    @override
    def load_base(self) -> int:
        if self._load_base is None:
            self._load_base = self.project.loader.main_object.mapped_base
        return self._load_base

    @override
    def normalize_addr(self, addr: int) -> int:
        if self.project.loader.main_object.pic:
            return addr - self.load_base
        return addr

    @override
    def denormalize_addr(self, addr: int) -> int:
        if self.project.loader.main_object.pic:
            return addr + self.load_base
        return addr

    @override
    def mem_addr_to_file_offset(self, addr: int) -> int:
        loader_addr = self.denormalize_addr(addr)
        file_addr = self.project.loader.main_object.addr_to_offset(loader_addr)
        if file_addr is None:
            raise ValueError(f"Memory address {hex(addr)} is not mapped to the file")
        return file_addr

    @override
    def get_basic_block(self, addr: int) -> BasicBlock:
        # NOTE: angr splits basic blocks at call instructions, so we need to handle this
        if self.is_thumb(addr) and addr % 2 == 0:
            addr += 1
        addr = self.denormalize_addr(addr)

        try:
            node = self.cfg.model.get_any_node(addr, anyaddr=True)
            if node is None:
                raise ValueError(f"Cannot find a CFG node containing address {hex(addr)}")
            func = self.project.kb.functions.function(node.function_address)
            func.normalize()
            ri = self.project.analyses.RegionIdentifier(func)
            graph = ri._graph.copy()
            ri._make_supergraph(graph)

            def _flatten(n):
                if hasattr(n, "nodes"):  # MultiNode
                    for sub in n.nodes:
                        yield from _flatten(sub)
                elif hasattr(n, "graph"):  # GraphRegion (angr >= 9.2.x)
                    for sub in n.graph.nodes():
                        yield from _flatten(sub)
                else:
                    yield n

            for multinode in graph.nodes():
                nodes = list(_flatten(multinode))
                cfg_blocks = [func.get_block(node.addr) for node in nodes]
                instr_addrs = sorted({instr_addr for b in cfg_blocks for instr_addr in b.instruction_addrs})
                if not instr_addrs:
                    continue
                start = min(b.addr for b in cfg_blocks)
                end = max(b.addr + b.size for b in cfg_blocks)
                size = end - start

                if addr in instr_addrs:
                    return BasicBlock(
                        start=self.normalize_addr(start),
                        size=size,
                        instruction_addrs=tuple(
                            self.normalize_addr(instr_addr)
                            - (1 if self.is_thumb(self.normalize_addr(instr_addr)) else 0)
                            for instr_addr in instr_addrs
                        ),
                    )
        except UnknownInstructionModeError:
            raise
        except Exception:  # noqa: BLE001
            logger.error(
                "angr RegionIdentifier failed for function containing %s; falling back to CFG nodes\n%s",
                hex(addr),
                traceback.format_exc(),
            )
            bb = None
            for node in self.cfg.model.nodes():
                if addr in node.instruction_addrs:
                    bb = node
                    break
            assert bb is not None
            return BasicBlock(
                start=self.normalize_addr(bb.addr),
                size=bb.size,
                instruction_addrs=tuple(
                    self.normalize_addr(addr) - (1 if self.is_thumb(self.normalize_addr(addr)) else 0)
                    for addr in bb.instruction_addrs
                ),
            )

        raise ValueError(f"Cannot find a block containing address {hex(addr)}")

    @override
    def get_instr_bytes_at(self, addr: int, num_instr: int = 1) -> bytes | None:
        addr += 1 if self.is_thumb(addr) else 0
        addr = self.denormalize_addr(addr)
        # TODO: Special handling for delay slot, when there is a call instr with delay slot
        # angr will return both instrs, even when num_instr is 1
        return self.project.factory.block(addr, num_inst=num_instr).bytes

    @override
    def get_unused_funcs(self) -> list[FunctionInfo]:
        logger.info("Getting unused functions with angr")
        unused_funcs: list[FunctionInfo] = []
        assert self.cfg is not None
        for func in self.project.kb.functions.values():
            if func.size == 0:
                continue
            for dst in self.project.kb.xrefs.xrefs_by_dst:
                if dst == func.addr:
                    break
            else:
                unused_funcs.append(
                    FunctionInfo(
                        addr=self.normalize_addr(func.addr)
                        - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                        size=func.size,
                    )
                )
        return unused_funcs

    @override
    def iter_symbols(self) -> Iterator[Symbol]:
        logger.info("Getting all symbols with angr")
        main_object = self.project.loader.main_object
        plt = getattr(main_object, "plt", {})
        for symbol in main_object.symbols:
            if not symbol.name or getattr(symbol, "is_common", False):
                continue
            # ARM mapping symbols ($a/$t/$d) mark instruction-set regions rather
            # than named data or code. _arm_mapping_symbols reads them directly
            # for thumb_mode; they are not symbols a patch can reference.
            if symbol.name in ("$a", "$t", "$d"):
                continue
            # An import is resolved from another object at load time, so it has
            # no address in this binary. angr reports the image base for these,
            # which is not a real location -- report None rather than passing on
            # a made-up address.
            if symbol.is_import or symbol.rebased_addr == main_object.mapped_base:
                yield ExternalSymbol(name=symbol.name)
                continue
            yield MappedSymbol(
                name=symbol.name,
                addr=self.normalize_addr(symbol.rebased_addr),
                is_stub=symbol.name in plt,
            )
        for func in self.project.kb.functions.values():
            # make it compatible with old angr versions
            # Default to False rather than falling back to func.alignment: that
            # attribute is the function's alignment *value*, not a flag, so a
            # non-zero alignment would drop a real function from the symbols.
            if func.is_simprocedure or getattr(func, "is_alignment", False):
                continue
            yield MappedSymbol(
                name=func.name,
                addr=self.normalize_addr(func.addr),
                is_stub=func.is_plt or func.name in plt,
            )

    @override
    def get_function(self, name_or_addr: int | str) -> FunctionInfo | None:
        assert self.cfg is not None
        if isinstance(name_or_addr, (str, int)):
            if isinstance(name_or_addr, int):
                name_or_addr += 1 if self.is_thumb(name_or_addr) else 0
                name_or_addr = self.denormalize_addr(name_or_addr)
            if name_or_addr in self.project.kb.functions:
                func = self.project.kb.functions[name_or_addr]
                return FunctionInfo(
                    addr=self.normalize_addr(func.addr) - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                    size=func.size,
                )
            return None
        else:
            raise TypeError(f"Invalid type for name_or_addr: {type(name_or_addr)}")

    @property
    def mapping_symbols(self) -> list[tuple[int, str]]:
        if self._mapping_symbols is None:
            self._mapping_symbols = sorted(
                (symbol.rebased_addr, symbol.name[:2])
                for symbol in self.project.loader.main_object.symbols
                if symbol.name and symbol.name[:2] in {"$a", "$d", "$t"}
            )
        return self._mapping_symbols

    def _mapping_thumb_mode(self, addr: int) -> tuple[bool, bool | None]:
        index = bisect_right(self.mapping_symbols, (addr, "\uffff")) - 1
        if index < 0:
            return False, None
        _, kind = self.mapping_symbols[index]
        if kind == "$t":
            return True, True
        if kind == "$a":
            return True, False
        return True, None

    def _cfg_thumb_mode(self, addr: int) -> bool | None:
        candidates = (addr, addr + 1) if addr % 2 == 0 else (addr,)
        modes = {
            node.thumb
            for node in self.cfg.model.nodes()
            if any(candidate in node.instruction_addrs for candidate in candidates)
        }
        if len(modes) != 1:
            return None
        return modes.pop()

    def thumb_mode(self, addr: int) -> bool | None:
        """Return the ARM instruction mode, or None when it is unknown."""
        if not isinstance(self.project.arch, ArchARM):
            return False

        addr = self.denormalize_addr(addr)
        mapping_found, mapping_mode = self._mapping_thumb_mode(addr)
        cfg_mode = self._cfg_thumb_mode(addr)

        if not mapping_found:
            return cfg_mode
        if cfg_mode is None:
            return mapping_mode
        if mapping_mode is not None and mapping_mode == cfg_mode:
            return mapping_mode
        return None

    @override
    def is_thumb(self, addr: int) -> bool:
        mode = self.thumb_mode(addr)
        if mode is None:
            addr = self.denormalize_addr(addr)
            raise UnknownInstructionModeError(f"Cannot determine ARM instruction mode at {hex(addr)}")
        return mode
