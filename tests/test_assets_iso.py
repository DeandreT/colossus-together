"""Synthetic ISO9660 fixtures only: no game image or external tools needed."""

import os

import pytest

from assets import IsoEntry, IsoError, IsoImage
from assets.iso import MAX_READ_BYTES, SECTOR_SIZE


def both(value, width):
    return value.to_bytes(width, "little") + value.to_bytes(width, "big")


def record(name, extent=24, size=3, flags=0):
    if isinstance(name, str):
        name = name.encode("ascii")
    data = bytearray(33 + len(name) + (len(name) % 2 == 0))
    data[0] = len(data)
    data[2:10] = both(extent, 4)
    data[10:18] = both(size, 4)
    data[25] = flags
    data[28:32] = both(1, 2)
    data[32] = len(name)
    data[33 : 33 + len(name)] = name
    return data


def image_bytes(root_records=None, root_size=SECTOR_SIZE, blocks=40):
    data = bytearray(blocks * SECTOR_SIZE)
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[:7] = b"\x01CD001\x01"
    descriptor[80:88] = both(blocks, 4)
    descriptor[120:124] = both(1, 2)
    descriptor[124:128] = both(1, 2)
    descriptor[128:132] = both(SECTOR_SIZE, 2)
    descriptor[156:190] = record(b"\0", 20, root_size, 2)
    descriptor[881] = 1
    data[16 * SECTOR_SIZE : 17 * SECTOR_SIZE] = descriptor
    if root_records is None:
        root_records = [
            record(b"\0", 20, root_size, 2),
            record(b"\1", 20, root_size, 2),
            record("GAMECORE.XFF;1"),
            record("SUBDIR", 21, SECTOR_SIZE, 2),
            record("EMPTY;1", 26, 0),
        ]
    root = b"".join(root_records)
    data[20 * SECTOR_SIZE : 20 * SECTOR_SIZE + len(root)] = root
    subdir = b"".join(
        [
            record(b"\0", 21, SECTOR_SIZE, 2),
            record(b"\1", 20, root_size, 2),
            record("MiXeD.BIN;1", 25, 5),
        ]
    )
    data[21 * SECTOR_SIZE : 21 * SECTOR_SIZE + len(subdir)] = subdir
    data[24 * SECTOR_SIZE : 24 * SECTOR_SIZE + 3] = b"xff"
    data[25 * SECTOR_SIZE : 25 * SECTOR_SIZE + 5] = b"hello"
    return data


@pytest.fixture
def make_iso(tmp_path):
    def make(data=None):
        path = tmp_path / "synthetic.iso"
        path.write_bytes(image_bytes() if data is None else data)
        return path

    return make


def test_root_nested_names_versions_and_extents(make_iso):
    with IsoImage(make_iso()) as image:
        entry = image.locate("gamecore.xff")
        assert entry == IsoEntry(24, 3, False)
        assert entry.offset == 24 * SECTOR_SIZE
        assert image.read_file("GAMECORE.XFF;1") == b"xff"
        assert image.read_file("subdir/mixed.bin;1") == b"hello"
        assert image.locate("SUBDIR").is_directory
        assert image.read_file("EMPTY", max_bytes=0) == b""
        assert list(image.iter_file("EMPTY")) == []


def test_read_only_open_and_lifetime(make_iso, monkeypatch):
    path = make_iso()
    original = path.read_bytes()
    actual_open = os.open
    calls = []

    def tracked_open(path, flags, *args, **kwargs):
        calls.append(flags)
        return actual_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracked_open)
    image = IsoImage(path)
    with pytest.raises(IsoError, match="with statement"):
        image.locate("GAMECORE.XFF")
    with image:
        handle = image._file
        assert not handle.writable()
        with pytest.raises(IsoError, match="already open"):
            image.__enter__()
    assert handle.closed
    assert calls and all(flags & os.O_ACCMODE == os.O_RDONLY for flags in calls)
    assert path.read_bytes() == original
    with pytest.raises(IsoError, match="with statement"):
        image.read_file("GAMECORE.XFF")
    with image:
        assert image.read_file("GAMECORE.XFF") == b"xff"


def test_nonregular_source_rejected(tmp_path):
    with pytest.raises(IsoError, match="regular file"), IsoImage(tmp_path):
        pass
    fifo = tmp_path / "source.fifo"
    os.mkfifo(fifo)
    with pytest.raises(IsoError, match="regular file"), IsoImage(fifo):
        pass


@pytest.mark.parametrize(
    "cut", [0, 16 * SECTOR_SIZE, 17 * SECTOR_SIZE - 1, 39 * SECTOR_SIZE]
)
def test_truncated_images(make_iso, cut):
    with (
        pytest.raises(IsoError, match="bounds|volume"),
        IsoImage(make_iso(image_bytes()[:cut])),
    ):
        pass


@pytest.mark.parametrize(
    "offset,value,message",
    [
        (0, 2, "Joliet-only"),
        (1, 0, "CD001"),
        (6, 2, "version 1"),
        (80 + 4, 1, "both-endian"),
        (128 + 2, 1, "both-endian"),
        (120 + 2, 1, "both-endian"),
        (124 + 2, 1, "both-endian"),
        (156, 33, "root record length"),
        (156 + 25, 0, "root directory"),
        (156 + 33, 1, "root directory"),
    ],
)
def test_invalid_primary_descriptor(make_iso, offset, value, message):
    data = image_bytes()
    data[16 * SECTOR_SIZE + offset] = value
    image = IsoImage(make_iso(data))
    with pytest.raises(IsoError, match=message):
        image.__enter__()
    assert image._file is None


@pytest.mark.parametrize(
    "offset,width,value,message",
    [
        (80, 4, 16, "volume bounds"),
        (80, 4, 41, "volume bounds"),
        (128, 2, 512, "2048-byte"),
        (120, 2, 2, "Multi-volume"),
        (124, 2, 2, "volume sequence"),
        (156 + 10, 4, 0, "Directory size"),
        (156 + 10, 4, 1024 * 1024 + 1, "bounds|Directory size"),
    ],
)
def test_consistent_but_unsupported_primary_values(
    make_iso, offset, width, value, message
):
    data = image_bytes()
    start = 16 * SECTOR_SIZE + offset
    data[start : start + 2 * width] = both(value, width)
    with pytest.raises(IsoError, match=message), IsoImage(make_iso(data)):
        pass


@pytest.mark.parametrize(
    "offset,value,message",
    [
        (0, 10, "record length"),
        (1, 1, "xattr"),
        (6, 1, "both-endian"),
        (14, 1, "both-endian"),
        (30, 1, "both-endian"),
        (25, 0x80, "Multi-extent"),
        (25, 0x04, "flags"),
        (25, 0x08, "flags"),
        (25, 0x10, "flags"),
        (25, 0x20, "flags"),
        (25, 0x40, "flags"),
        (26, 1, "Interleaved"),
        (27, 1, "Interleaved"),
        (32, 255, "filename"),
        (32, 0, "filename"),
    ],
)
def test_bad_directory_records(make_iso, offset, value, message):
    entry = record("GAMECORE.XFF;1")
    entry[offset] = value
    with (
        IsoImage(make_iso(image_bytes([entry]))) as image,
        pytest.raises(IsoError, match=message),
    ):
        image.locate("GAMECORE.XFF")


@pytest.mark.parametrize(
    "extent,size", [(40, 0), (40, 1), (39, SECTOR_SIZE + 1), (2**32 - 1, 3)]
)
def test_extents_outside_volume(make_iso, extent, size):
    with (
        IsoImage(make_iso(image_bytes([record("BAD", extent, size)]))) as image,
        pytest.raises(IsoError, match="bounds"),
    ):
        image.locate("BAD")


def test_volume_not_trailing_image_is_the_bound(make_iso):
    data = image_bytes([record("BAD", 40, 1)]) + bytearray(10 * SECTOR_SIZE)
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="bounds"):
        image.locate("BAD")


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/GAMECORE.XFF",
        "GAMECORE.XFF/",
        "SUBDIR//MiXeD.BIN",
        ".",
        "..",
        "SUBDIR/../GAMECORE.XFF",
        "SUBDIR/./MiXeD.BIN",
        "SUBDIR\\MiXeD.BIN",
        "C:GAMECORE.XFF",
        "C:/GAMECORE.XFF",
        "gáme",
        "GAME\0CORE",
        "GAME\nCORE",
        ";1",
        "..;1",
        ".;1",
        "/".join(["A"] * 17),
        None,
    ],
)
def test_reject_bad_paths(make_iso, path):
    with IsoImage(make_iso()) as image, pytest.raises(IsoError):
        image.locate(path)


@pytest.mark.parametrize(
    "name", [b"G\xff", b"../BAD", b"..", b".", b"BAD\\NAME", b"C:BAD", b"BAD\0NAME"]
)
def test_reject_bad_iso_names(make_iso, name):
    with (
        IsoImage(make_iso(image_bytes([record(name)]))) as image,
        pytest.raises(IsoError),
    ):
        image.locate("GAMECORE.XFF")


def test_duplicate_case_version_names(make_iso):
    entries = [record("GAMECORE.XFF;1"), record("gamecore.xff")]
    with (
        IsoImage(make_iso(image_bytes(entries))) as image,
        pytest.raises(IsoError, match="Ambiguous duplicate"),
    ):
        image.locate("GAMECORE.XFF")


def test_directory_cycle(make_iso):
    entries = [record("LOOP", 20, SECTOR_SIZE, 2)]
    with (
        IsoImage(make_iso(image_bytes(entries))) as image,
        pytest.raises(IsoError, match="cycle"),
    ):
        image.locate("LOOP/GAMECORE.XFF")


def test_indirect_directory_cycle(make_iso):
    data = image_bytes([record("CHILD", 21, SECTOR_SIZE, 2)])
    child = record("BACK", 20, SECTOR_SIZE, 2)
    data[21 * SECTOR_SIZE : 22 * SECTOR_SIZE] = child + bytes(SECTOR_SIZE - len(child))
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="cycle"):
        image.locate("CHILD/BACK")


def test_zero_padding_jumps_to_next_sector(make_iso):
    data = image_bytes([], root_size=2 * SECTOR_SIZE)
    # Root sector is entirely padding; next sector still contains valid entries.
    with IsoImage(make_iso(data)) as image:
        assert image.read_file("MiXeD.BIN") == b"hello"


def test_nonzero_after_zero_padding_rejected(make_iso):
    data = image_bytes([])
    data[20 * SECTOR_SIZE + 50] = 1
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="padding"):
        image.locate("A")


def test_record_crossing_sector_rejected(make_iso):
    # Valid small records and a final filler end at byte 2040.
    records = [record(f"{i}", 24, 0) for i in range(10)]
    records += [record(f"{i:02}", 24, 0) for i in range(10, 56)]
    prefix = b"".join(records)
    # Fill to exactly 2040 with a well-formed record and system-use bytes.
    filler = record("F", 24, 0)
    filler.extend(bytes(2040 - len(prefix) - len(filler)))
    filler[0] = len(filler)
    data = image_bytes([], root_size=2 * SECTOR_SIZE)
    data[20 * SECTOR_SIZE : 20 * SECTOR_SIZE + 2040] = prefix + filler
    data[20 * SECTOR_SIZE + 2040] = 34
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="crosses"):
        image.locate("A")


def test_record_crossing_directory_end_rejected(make_iso):
    data = image_bytes([record("GAMECORE.XFF")], root_size=35)
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="crosses"):
        image.locate("GAMECORE.XFF")


def test_filename_padding_rejected(make_iso):
    item = record("AB")
    item[-1] = 1
    with (
        IsoImage(make_iso(image_bytes([item]))) as image,
        pytest.raises(IsoError, match="filename padding"),
    ):
        image.locate("AB")


def test_directory_size_limit(make_iso):
    data = image_bytes(blocks=600)
    data[16 * SECTOR_SIZE + 166 : 16 * SECTOR_SIZE + 174] = both(1024 * 1024 + 1, 4)
    with pytest.raises(IsoError, match="1 MiB"), IsoImage(make_iso(data)):
        pass


def test_directory_entry_limit(make_iso):
    sectors = []
    sector = bytearray()
    for index in range(4097):
        item = record(f"F{index}", 199, 0)
        if len(sector) + len(item) > SECTOR_SIZE:
            sectors.append(sector + bytes(SECTOR_SIZE - len(sector)))
            sector = bytearray()
        sector += item
    sectors.append(sector + bytes(SECTOR_SIZE - len(sector)))
    directory = b"".join(sectors)
    data = image_bytes([], root_size=len(directory), blocks=200)
    data[20 * SECTOR_SIZE : 20 * SECTOR_SIZE + len(directory)] = directory
    with IsoImage(make_iso(data)) as image, pytest.raises(IsoError, match="4096-entry"):
        image.locate("F0")


def test_sixteen_path_components_supported(make_iso):
    data = image_bytes([record("D", 21, SECTOR_SIZE, 2)], blocks=50)
    for extent in range(21, 35):
        item = record("D", extent + 1, SECTOR_SIZE, 2)
        data[extent * SECTOR_SIZE : (extent + 1) * SECTOR_SIZE] = item + bytes(
            SECTOR_SIZE - len(item)
        )
    item = record("LAST", 40, 3)
    data[35 * SECTOR_SIZE : 36 * SECTOR_SIZE] = item + bytes(SECTOR_SIZE - len(item))
    data[40 * SECTOR_SIZE : 40 * SECTOR_SIZE + 3] = b"end"
    with IsoImage(make_iso(data)) as image:
        assert image.read_file("/".join(["D"] * 15 + ["LAST"])) == b"end"


def test_file_and_directory_errors(make_iso):
    with IsoImage(make_iso()) as image:
        with pytest.raises(FileNotFoundError):
            image.locate("MISSING")
        with pytest.raises(IsoError, match="traverse through a file"):
            image.locate("GAMECORE.XFF/OTHER")
        with pytest.raises(IsoError, match="not a file"):
            image.read_file("SUBDIR")
        with pytest.raises(IsoError, match="not a file"):
            list(image.iter_file("SUBDIR"))


@pytest.mark.parametrize("limit", [-1, 1.5, None, True])
def test_invalid_whole_file_limits(make_iso, limit):
    with IsoImage(make_iso()) as image, pytest.raises(IsoError, match="max_bytes"):
        image.read_file("GAMECORE.XFF", max_bytes=limit)


@pytest.mark.parametrize("chunk", [0, -1, MAX_READ_BYTES + 1, 1.5, None, True])
def test_invalid_chunk_sizes(make_iso, chunk):
    with IsoImage(make_iso()) as image, pytest.raises(IsoError, match="chunk_size"):
        list(image.iter_file("GAMECORE.XFF", chunk_size=chunk))


def test_chunked_reads_and_interleaved_iterators(make_iso):
    with IsoImage(make_iso()) as image:
        assert list(image.iter_file("SUBDIR/MIXED.BIN", chunk_size=2)) == [
            b"he",
            b"ll",
            b"o",
        ]
        first = image.iter_file("GAMECORE.XFF", chunk_size=1)
        second = image.iter_file("SUBDIR/MIXED.BIN", chunk_size=2)
        assert next(first) == b"x"
        assert next(second) == b"he"
        assert next(first) == b"f"
        assert b"".join(second) == b"llo"
        assert b"".join(first) == b"f"


def test_large_file_rejected_before_payload_read_and_streamed_bounded(
    make_iso, monkeypatch
):
    size = MAX_READ_BYTES + 17
    blocks = 25 + (size + SECTOR_SIZE - 1) // SECTOR_SIZE
    data = image_bytes([record("NICO.DAT;1", 24, size)], blocks=blocks)
    path = make_iso(data)
    with IsoImage(path) as image:
        actual_read = image._read
        sizes = []

        def tracked_read(offset, length):
            sizes.append(length)
            return actual_read(offset, length)

        monkeypatch.setattr(image, "_read", tracked_read)
        with pytest.raises(IsoError, match="max_bytes"):
            image.read_file("NICO.DAT")
        assert max(sizes) <= SECTOR_SIZE
        sizes.clear()
        total = 0
        for chunk in image.iter_file("NICO.DAT", chunk_size=65536):
            assert 0 < len(chunk) <= 65536
            total += len(chunk)
        assert total == size
        assert max(sizes) <= 65536
        assert len(image.read_file("NICO.DAT", max_bytes=size)) == size


def test_truncation_after_open_is_detected(make_iso):
    path = make_iso()
    with IsoImage(path) as image:
        path.write_bytes(path.read_bytes()[: 22 * SECTOR_SIZE])
        with pytest.raises(IsoError, match="Truncated"):
            image.read_file("GAMECORE.XFF")


def test_iterator_requires_live_context(make_iso):
    with IsoImage(make_iso()) as image:
        chunks = image.iter_file("GAMECORE.XFF", chunk_size=1)
        assert next(chunks) == b"x"
    with pytest.raises(IsoError, match="with statement"):
        next(chunks)
