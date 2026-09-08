import pytest
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

from patcherex2 import ComponentOverrides, PatchSession, TargetConfig
from patcherex2.components.allocation_manager import MemoryFlag
from patcherex2.components.placement_strategies import BareMetalAddressSpace, ElfExplicitPlacement
from patcherex2.targets import ARM_MIMXRT1052_ELF
from tests.support.fakes import FakeBinaryAnalyzer, FakeCompiler
from tests.support.paths import TEST_BINARIES


@pytest.mark.parametrize(
    ("flag", "section_flags"),
    [
        (MemoryFlag.RX, SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR),
        (MemoryFlag.RW, SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE),
    ],
)
def test_board_target_emits_authorized_segments_and_relocated_headers(
    tmp_path, flag, section_flags
):
    with PatchSession.load_binary(
        TEST_BINARIES / "armhf/printf_nopie",
        target=ARM_MIMXRT1052_ELF,
        config=TargetConfig(
            overrides=ComponentOverrides(
                placement=ElfExplicitPlacement(
                    BareMetalAddressSpace(
                        unused_flash=(range(0x60000000, 0x60001000),),
                        unused_ram=(range(0x80000000, 0x80001000),),
                    )
                ),
            )
        ),
        binary_analyzer=FakeBinaryAnalyzer(),
        compiler=FakeCompiler(),
    ) as session:
        block = session.allocation_manager.allocate(4, flag=flag)
        session.image.update_binary_content(block.file_addr, b"TEST")
        # Exercise image emission independently of the startup-instruction policy.
        session.image.finalize(session.allocation_manager, session.binary_analyzer)
        output = tmp_path / "board.elf"
        session.save_binary(str(output))

    with output.open("rb") as stream:
        elf = ELFFile(stream)
        segments = list(elf.iter_segments())
        assert all(segment["p_type"] != "PT_PHDR" for segment in segments)
        loads = [segment for segment in segments if segment["p_type"] == "PT_LOAD"]
        addresses = [segment["p_vaddr"] for segment in loads]
        assert addresses == sorted(addresses)
        added = next(segment for segment in loads if segment["p_offset"] == block.file_addr)
        assert added["p_paddr"] == 0x60000000
        assert added["p_vaddr"] == (0x80000000 if flag == MemoryFlag.RW else 0x60000000)
        assert added["p_filesz"] == added["p_memsz"] == 4
        assert added.data() == b"TEST"
        section = next(
            section for section in elf.iter_sections() if section["sh_offset"] == block.file_addr
        )
        assert section["sh_flags"] == section_flags


def test_board_target_requires_caller_authorization():
    with (
        pytest.raises(ValueError, match="ElfExplicitPlacement"),
        PatchSession.load_binary("unused.elf", target=ARM_MIMXRT1052_ELF),
    ):
        pass
