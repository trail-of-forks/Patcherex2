#!/usr/bin/env python

# ruff: noqa
import bisect
import os

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2.components.binary_analyzers.angr import AngrAnalyzer

bin_location = str(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_binaries/armhf")
)

MAPPING_KINDS = {"$t": True, "$a": False, "$d": None}


def mode_from_elf(analyzer, loaded_addr):
    """Instruction set at an address per the ELF mapping symbols alone."""
    addrs, kinds = analyzer._arm_mapping_symbols
    idx = bisect.bisect_right(addrs, loaded_addr) - 1
    if idx < 0:
        return None
    return MAPPING_KINDS[kinds[idx]]


def thumb_regions(analyzer):
    """(start, end) of each $t region, bounded by the next mapping symbol."""
    addrs, kinds = analyzer._arm_mapping_symbols
    return [
        (addr, addrs[i + 1] if i + 1 < len(addrs) else addr + 2)
        for i, (addr, kind) in enumerate(zip(addrs, kinds))
        if kind == "$t"
    ]


@pytest.fixture(scope="module")
def nopie():
    a = AngrAnalyzer(os.path.join(bin_location, "printf_nopie"))
    a.cfg  # force recovery
    return a


@pytest.fixture(scope="module")
def pie():
    a = AngrAnalyzer(os.path.join(bin_location, "printf_pie"))
    a.cfg
    return a


class TestThumbMode:
    def test_cfg_uncovered_thumb_address_is_not_reported_as_arm(self, nopie):
        """
        The issue-38 case: addresses inside a $t region that no recovered basic
        block covers. These used to return False ("ARM"), which decodes two
        16-bit Thumb instructions as one 32-bit ARM instruction and relocates an
        instruction that is not in the binary.
        """
        covered = set()
        for node in nopie.cfg.model.nodes():
            covered.update(node.instruction_addrs)

        regions = thumb_regions(nopie)
        assert regions, "test binary has no Thumb regions"

        uncovered = [
            addr
            for start, end in regions
            for addr in range(start, end, 2)
            if addr not in covered and (addr | 1) not in covered
        ]
        assert uncovered, "no CFG-uncovered Thumb addresses to exercise"

        for addr in uncovered:
            norm = nopie.normalize_addr(addr)
            assert nopie.is_thumb(norm) is True, hex(addr)
            assert nopie.thumb_mode(norm) is True, hex(addr)

    def test_arm_regions_still_report_arm(self, nopie):
        for addr, kind in zip(*nopie._arm_mapping_symbols):
            if kind != "$a":
                continue
            norm = nopie.normalize_addr(addr)
            if nopie.thumb_mode(norm) is None:
                continue
            assert nopie.is_thumb(norm) is False, hex(addr)

    def test_thumb_boundaries_report_thumb(self, nopie):
        for addr, kind in zip(*nopie._arm_mapping_symbols):
            if kind != "$t":
                continue
            assert nopie.is_thumb(nopie.normalize_addr(addr)) is True, hex(addr)

    def test_data_region_is_undeterminable_not_arm(self, nopie):
        """$d is data, so no instruction set applies: thumb_mode says so."""
        data_addrs = [
            addr for addr, kind in zip(*nopie._arm_mapping_symbols) if kind == "$d"
        ]
        assert data_addrs
        assert any(
            nopie.thumb_mode(nopie.normalize_addr(a)) is None for a in data_addrs
        )

    def test_is_thumb_stays_boolean(self, nopie):
        """
        is_thumb has ~20 call sites doing `1 if is_thumb(x) else 0`; it must never
        return None, or they would silently take the ARM branch.
        """
        addrs, _ = nopie._arm_mapping_symbols
        # Includes addresses past the last region, where nothing can resolve the
        # mode -- is_thumb must still hand back a bool there.
        probe = list(addrs) + [addrs[-1] + 2, addrs[-1] + 0x1000]
        for addr in probe:
            assert isinstance(nopie.is_thumb(nopie.normalize_addr(addr)), bool), hex(
                addr
            )

    def test_cfg_wins_over_incomplete_mapping_symbols(self, pie):
        """
        Mapping symbols must not override recovered code. printf_pie has $t at
        0x500 covering Thumb frame_dummy, but no $a marking ARM main at 0x504 --
        the symbols alone imply Thumb for an ARM function.
        """
        main_norm = 0x504
        assert mode_from_elf(pie, pie.denormalize_addr(main_norm)) is True, (
            "precondition: mapping symbols should mislead here"
        )
        assert pie.thumb_mode(main_norm) is False
        assert pie.is_thumb(main_norm) is False

    def test_non_arm_arch_is_never_thumb(self):
        amd64 = AngrAnalyzer(os.path.join(bin_location, "..", "amd64", "printf_nopie"))
        assert amd64.is_thumb(0x401000) is False
        assert amd64.thumb_mode(0x401000) is False


def elf_thumb_regions(path):
    """
    $t regions read straight from the ELF with pyelftools.

    Deliberately independent of the analyzer under test: a regression test that
    sourced its ground truth from AngrAnalyzer._arm_mapping_symbols would still pass if
    the lookup were reverted, since it would simply find no regions to check.
    """
    with open(path, "rb") as f:
        elf = ELFFile(f)
        marks = sorted(
            (sym["st_value"], sym.name)
            for section in elf.iter_sections()
            if section.header["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM")
            for sym in section.iter_symbols()
            if sym.name in ("$a", "$t", "$d")
        )
    return [
        (addr, marks[i + 1][0] if i + 1 < len(marks) else addr + 2)
        for i, (addr, kind) in enumerate(marks)
        if kind == "$t"
    ]


class TestAgreementWithElf:
    """
    Sweep against ground truth read independently from the ELF: a Thumb address
    the CFG does not cover must not come back as ARM.
    """

    @pytest.mark.parametrize(
        "binary", ["printf_nopie", "printf_pie", "iip_c", "replace_function_patch"]
    )
    def test_no_thumb_region_reported_as_arm(self, binary):
        path = os.path.join(bin_location, binary)
        regions = elf_thumb_regions(path)
        assert regions, f"{binary}: no $t regions found in the ELF"

        a = AngrAnalyzer(path)
        a.cfg
        covered = set()
        for node in a.cfg.model.nodes():
            covered.update(node.instruction_addrs)

        # ELF symbol values are unrebased; match them to the analyzer's space.
        base = a.p.loader.main_object.mapped_base if a.p.loader.main_object.pic else 0

        disagreements = []
        checked = 0
        for start, end in regions:
            for addr in range(start + base, end + base, 2):
                # Only where the CFG cannot speak: that is the fallback path.
                if addr in covered or (addr | 1) in covered:
                    continue
                checked += 1
                if a.is_thumb(a.normalize_addr(addr)) is not True:
                    disagreements.append(hex(addr))

        assert checked, f"{binary}: no CFG-uncovered Thumb addresses to check"
        assert not disagreements, (
            f"{binary}: {len(disagreements)}/{checked} Thumb addresses reported "
            f"as ARM: {disagreements[:10]}"
        )
