from __future__ import annotations

import bisect
import logging
import traceback
from typing import final

import angr
from archinfo import ArchARM

from .binary_analyzer import BinaryAnalyzer

logger = logging.getLogger(__name__)


@final
class AngrAnalyzer(BinaryAnalyzer):
    def __init__(self, binary_path: str, **kwargs) -> None:
        self.binary_path = binary_path
        # self.use_pickle = kwargs.pop("use_pickle", False) # TODO: implement this
        self.angr_kwargs = kwargs.pop("angr_kwargs", {})
        self.angr_cfg_kwargs = kwargs.pop("angr_cfg_kwargs", {})
        self._p = None
        self._cfg = None
        self._load_base = None
        self._mapping_symbols = None

    @property
    def load_base(self) -> int:
        if self._load_base is None:
            self._load_base = self.p.loader.main_object.mapped_base
        return self._load_base

    def normalize_addr(self, addr: int) -> int:
        if self.p.loader.main_object.pic:
            return addr - self.load_base
        return addr

    def denormalize_addr(self, addr: int) -> int:
        if self.p.loader.main_object.pic:
            return addr + self.load_base
        return addr

    @property
    def p(self) -> angr.Project:
        if self._p is None:
            logger.info("Loading binary with angr")
            if "load_options" not in self.angr_kwargs:
                self.angr_kwargs["load_options"] = {"auto_load_libs": False}
            self._p = angr.Project(self.binary_path, **self.angr_kwargs)
            logger.info("Loaded binary with angr")
        return self._p

    @property
    def cfg(self) -> angr.analyses.cfg.cfg_fast.CFGFast:
        if self._cfg is None:
            logger.info("Generating CFG with angr")
            if "normalize" not in self.angr_cfg_kwargs:
                # NOTE: This will split basic blocks if another block jumps to the middle of the block
                self.angr_cfg_kwargs["normalize"] = True
            self._cfg = self.p.analyses.CFGFast(**self.angr_cfg_kwargs)
            logger.info("Generated CFG with angr")
        return self._cfg

    def mem_addr_to_file_offset(self, addr: int) -> int:
        addr = self.denormalize_addr(addr)
        file_addr = self.p.loader.main_object.addr_to_offset(addr)
        if file_addr is None:
            logger.error(
                f"Cannot convert memory address {hex(addr)} to file offset, will use the memory address instead"
            )
            return addr
        return file_addr

    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        # NOTE: angr splits basic blocks at call instructions, so we need to handle this
        if self.is_thumb(addr) and addr % 2 == 0:
            addr += 1
        addr = self.denormalize_addr(addr)

        try:
            func = self.p.kb.functions.function(
                self.cfg.model.get_any_node(addr, anyaddr=True).function_address
            )
            func.normalize()
            ri = self.p.analyses.RegionIdentifier(func)
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
                instr_addrs = sorted(
                    {
                        instr_addr
                        for b in cfg_blocks
                        for instr_addr in b.instruction_addrs
                    }
                )
                if not instr_addrs:
                    continue
                start = min(b.addr for b in cfg_blocks)
                end = max(b.addr + b.size for b in cfg_blocks)
                size = end - start

                if addr in instr_addrs:
                    return {
                        "start": self.normalize_addr(start),
                        "end": self.normalize_addr(end),
                        "size": size,
                        "instruction_addrs": [
                            self.normalize_addr(instr_addr)
                            - (
                                1
                                if self.is_thumb(self.normalize_addr(instr_addr))
                                else 0
                            )
                            for instr_addr in instr_addrs
                        ],
                    }
        except Exception:  # noqa: BLE001
            logger.error(
                f"angr RegionIdentifier failed for function containing {hex(addr)}, falling back to use cfg nodes\n{traceback.format_exc()}"
            )
            bb = None
            for node in self.cfg.model.nodes():
                if addr in node.instruction_addrs:
                    bb = node
                    break
            assert bb is not None
            return {
                "start": self.normalize_addr(bb.addr),
                "end": self.normalize_addr(bb.addr + bb.size),
                "size": bb.size,
                "instruction_addrs": [
                    self.normalize_addr(addr)
                    - (1 if self.is_thumb(self.normalize_addr(addr)) else 0)
                    for addr in bb.instruction_addrs
                ],
            }

        raise ValueError(f"Cannot find a block containing address {hex(addr)}")

    def get_instr_bytes_at(self, addr: int, num_instr: int = 1) -> bytes | None:
        addr += 1 if self.is_thumb(addr) else 0
        addr = self.denormalize_addr(addr)
        # TODO: Special handling for delay slot, when there is a call instr with delay slot
        # angr will return both instrs, even when num_instr is 1
        return self.p.factory.block(addr, num_inst=num_instr).bytes

    def get_unused_funcs(self) -> list[dict[str, int]]:
        logger.info("Getting unused functions with angr")
        unused_funcs = []
        assert self.cfg is not None
        for func in self.p.kb.functions.values():
            if func.size == 0:
                continue
            for dst in self.p.kb.xrefs.xrefs_by_dst:
                if dst == func.addr:
                    break
            else:
                unused_funcs.append(
                    {
                        "addr": self.normalize_addr(func.addr)
                        - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                        "size": func.size,
                    }
                )
        return unused_funcs

    def get_all_symbols(self) -> dict[str, int]:
        assert self.cfg is not None
        logger.info("Getting all symbols with angr")
        symbols = {}
        for symbol in self.p.loader.main_object.symbols:
            if not symbol.name or not symbol.is_function:
                continue
            symbols[symbol.name] = self.normalize_addr(symbol.rebased_addr)
        for func in self.p.kb.functions.values():
            # make it compatible with old angr versions
            if func.is_simprocedure or getattr(
                func, "is_alignment", getattr(func, "alignment", False)
            ):
                continue
            symbols[func.name] = self.normalize_addr(func.addr)
        return symbols

    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        assert self.cfg is not None
        if isinstance(name_or_addr, (str, int)):
            if isinstance(name_or_addr, int):
                name_or_addr += 1 if self.is_thumb(name_or_addr) else 0
                name_or_addr = self.denormalize_addr(name_or_addr)
            if name_or_addr in self.p.kb.functions:
                func = self.p.kb.functions[name_or_addr]
                return {
                    "addr": self.normalize_addr(func.addr)
                    - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                    "size": func.size,
                }
            return None
        else:
            raise TypeError(f"Invalid type for name_or_addr: {type(name_or_addr)}")

    @property
    def _arm_mapping_symbols(self) -> tuple[list[int], list[str]]:
        """
        ARM ELF ``$a``/``$t``/``$d`` mapping symbols as parallel sorted lists of
        addresses and kinds.

        Each symbol marks the *start* of a region that runs until the next one
        (they carry no size). They are present even where CFG recovery is
        partial, which is what makes them useful as a fallback, but they are not
        always complete -- see :meth:`thumb_mode` for why they do not override
        the CFG.

        Addresses are returned separately because bisect needs a bare key list.
        """
        if self._mapping_symbols is None:
            symbols = sorted(
                (sym.rebased_addr, sym.name)
                for sym in self.p.loader.main_object.symbols
                if sym.name in ("$a", "$t", "$d")
            )
            self._mapping_symbols = (
                [sym_addr for sym_addr, _ in symbols],
                [kind for _, kind in symbols],
            )
            logger.debug(f"Found {len(symbols)} ARM mapping symbols")
        return self._mapping_symbols

    def _thumb_from_mapping_symbols(self, addr: int) -> bool | None:
        """
        Instruction set at ``addr`` per the ELF mapping symbols, or None if they
        do not cover it. ``addr`` is a denormalized (loaded) address.

        A ``$d`` region is data, not code, so no instruction set applies and this
        reports None rather than guessing.
        """
        addrs, kinds = self._arm_mapping_symbols
        idx = bisect.bisect_right(addrs, addr) - 1
        if idx < 0:
            return None
        if kinds[idx] == "$t":
            return True
        if kinds[idx] == "$a":
            return False
        return None

    def thumb_mode(self, addr: int) -> bool | None:
        """
        Whether ``addr`` is Thumb, or None when it genuinely cannot be determined.

        Unlike :meth:`is_thumb` this does not fall back to a guess, so a caller
        that is able to refuse an address can tell "definitely ARM" apart from
        "no idea".

        The CFG is consulted first: where recovery succeeded it decoded actual
        instructions, which is stronger evidence than a mapping symbol. Mapping
        symbols are used only where the CFG has nothing, which is the case the
        old fallback answered with a bare "ARM".

        Note that mapping symbols alone are *not* reliable enough to override the
        CFG: toolchains omit them. In ``printf_pie`` the ``$t`` at ``0x500``
        covers Thumb ``frame_dummy`` but no ``$a`` marks ARM ``main`` at
        ``0x504``, so the symbols imply Thumb for an ARM function.

        :param addr: The address to query, in the same (normalized) convention
            the other methods here take.
        :return: True for Thumb, False for ARM, None if undeterminable.
        """
        if not isinstance(self.p.arch, ArchARM):
            return False
        loaded_addr = self.denormalize_addr(addr)

        # Thumb instructions sit at odd addresses in angr's model, so an even
        # address may be recorded either way; check both parities.
        for candidate in (loaded_addr, loaded_addr | 1):
            for node in self.cfg.model.nodes():
                if candidate in node.instruction_addrs:
                    return node.thumb

        return self._thumb_from_mapping_symbols(loaded_addr)

    def is_thumb(self, addr: int) -> bool:
        """
        Whether ``addr`` is Thumb, defaulting to ARM when undeterminable.

        Prefer :meth:`thumb_mode` where an undeterminable address can be
        refused: decoding Thumb bytes as ARM fuses two 16-bit instructions into
        one, so a wrong answer here silently relocates instructions that do not
        exist in the binary.
        """
        mode = self.thumb_mode(addr)
        if mode is None:
            logger.warning(
                f"Cannot determine whether {hex(addr)} is ARM or Thumb: no "
                f"mapping symbol or recovered basic block covers it. Assuming "
                f"ARM, which will decode incorrectly if it is in fact Thumb. "
                f"Use thumb_mode() to detect this case."
            )
            return False
        return mode
