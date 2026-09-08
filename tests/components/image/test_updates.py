import inspect
from pathlib import Path

import pytest
from intelhex import IntelHex

from patcherex2.components.image import ImageBackend
from patcherex2.components.image.elf import ElfImageBackend
from patcherex2.components.image.ihex import IHexImageBackend
from patcherex2.components.image.raw import RawImageBackend
from tests.support.paths import TEST_BINARIES

ORIGINAL_CONTENT = b"abcdefghijklmnopqrstuvwxyz012345"


def test_image_backend_declares_required_abstract_contract():
    assert inspect.isabstract(ImageBackend)
    assert ImageBackend.__abstractmethods__ == {
        "finalize",
        "get_binary_content",
        "is_position_independent",
        "page_alignment",
        "save_binary",
    }

    with pytest.raises(TypeError, match="abstract"):
        ImageBackend("firmware", file_size=0)  # pyright: ignore[reportAbstractUsage]


@pytest.mark.parametrize("backend_type", [ElfImageBackend, RawImageBackend, IHexImageBackend])
def test_builtin_image_backends_are_concrete(backend_type):
    assert not inspect.isabstract(backend_type)


def test_backend_base_initializes_per_instance_image_state(tmp_path):
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(b"abc")
    second_path.write_bytes(b"defgh")

    first = RawImageBackend(first_path)
    second = RawImageBackend(second_path)
    first.update_binary_content(0, b"A")

    assert first.file_size == 3
    assert second.file_size == 5
    assert len(first.file_updates) == 1
    assert second.file_updates == []


def make_image_backend(tool_type: type[ImageBackend], tmp_path: Path) -> ImageBackend:
    if tool_type is ElfImageBackend:
        return ElfImageBackend(str(TEST_BINARIES / "amd64/printf_nopie"))

    input_path = tmp_path / f"{tool_type.__name__}.input"
    if tool_type is RawImageBackend:
        input_path.write_bytes(ORIGINAL_CONTENT)
        return RawImageBackend(str(input_path))

    ihex = IntelHex()
    ihex.frombytes(ORIGINAL_CONTENT)
    ihex.write_hex_file(str(input_path))
    return IHexImageBackend(str(input_path))


@pytest.fixture(params=[ElfImageBackend, RawImageBackend, IHexImageBackend])
def image(request, tmp_path):
    backend = make_image_backend(request.param, tmp_path)
    original = backend.get_binary_content(0, backend.file_size)
    return backend, original


def test_staged_updates_overlay_partial_reads_for_all_binary_formats(image):
    backend, original = image
    backend.update_binary_content(3, b"XYZ")

    assert backend.get_binary_content(2, 5) == original[2:3] + b"XYZ" + original[6:7]


def test_interval_conflicts_are_rejected_for_all_binary_formats(image):
    backend, _original = image
    backend.update_binary_content(3, b"XYZ")

    with pytest.raises(ValueError, match="conflicts with a previous update interval"):
        backend.update_binary_content(2, b"QQQ")


def test_update_bridges_compatible_intervals_for_all_binary_formats(image):
    backend, original = image
    backend.update_binary_content(2, original[2:4])
    backend.update_binary_content(6, original[6:8])
    backend.update_binary_content(3, original[3:7])

    assert backend.get_binary_content(2, 6) == original[2:8]


@pytest.mark.parametrize(
    ("old_start", "old_end", "new_start", "new_end", "merged_start", "merged_end"),
    [
        (4, 8, 4, 8, 4, 8),
        (4, 8, 5, 7, 4, 8),
        (5, 7, 4, 8, 4, 8),
        (5, 9, 3, 7, 3, 9),
        (3, 7, 5, 9, 3, 9),
    ],
)
def test_idempotent_overlaps_preserve_combined_content(
    old_start, old_end, new_start, new_end, merged_start, merged_end, tmp_path
):
    tool = make_image_backend(RawImageBackend, tmp_path)
    replacement = b"X" * (merged_end - merged_start)
    tool.update_binary_content(
        old_start,
        replacement[old_start - merged_start : old_end - merged_start],
    )
    tool.update_binary_content(
        new_start,
        replacement[new_start - merged_start : new_end - merged_start],
    )
    expected = bytearray(ORIGINAL_CONTENT)
    expected[merged_start:merged_end] = replacement

    assert tool.get_binary_content(0, tool.file_size) == bytes(expected)


def test_disjoint_updates_are_read_in_recording_independent_order(tmp_path):
    tool = make_image_backend(RawImageBackend, tmp_path)
    tool.update_binary_content(12, b"cd")
    tool.update_binary_content(2, b"ab")
    expected = bytearray(ORIGINAL_CONTENT)
    expected[2:4] = b"ab"
    expected[12:14] = b"cd"

    assert tool.get_binary_content(0, tool.file_size) == bytes(expected)


@pytest.mark.parametrize(
    ("old_start", "old_content", "new_start", "new_content"),
    [
        (4, b"abcd", 5, b"XX"),
        (5, b"bc", 4, b"aXXd"),
        (5, b"bcd", 3, b"abX"),
        (3, b"abc", 5, b"XXd"),
    ],
)
def test_conflicting_overlaps_are_rejected_in_both_directions(
    old_start, old_content, new_start, new_content, tmp_path
):
    tool = make_image_backend(RawImageBackend, tmp_path)
    tool.update_binary_content(old_start, old_content)

    with pytest.raises(ValueError, match="conflicts with a previous update interval"):
        tool.update_binary_content(new_start, new_content)

    assert tool.get_binary_content(old_start, len(old_content)) == old_content


def test_empty_update_is_a_noop(tmp_path):
    tool = make_image_backend(RawImageBackend, tmp_path)

    tool.update_binary_content(4, b"")

    assert tool.get_binary_content(0, tool.file_size) == ORIGINAL_CONTENT


def test_negative_update_offset_is_rejected(tmp_path):
    tool = make_image_backend(RawImageBackend, tmp_path)

    with pytest.raises(ValueError, match="negative file offset"):
        tool.update_binary_content(-1, b"x")
