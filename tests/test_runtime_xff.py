"""Synthetic XFF fixtures only; no disc assets or decomp dependencies."""

import struct

import pytest

from runtime import xff
from runtime.xff_bindings import Metadata


def fixture():
    """Build the documented wire layout independently of production parsing."""
    names = ['', '.text', '.bss', '.symtab', '.strtab', '.shstrtab']
    shstrings = b''
    offsets = []
    for name in names:
        offsets.append(len(shstrings))
        shstrings += name.encode() + b'\0'
    strings = b'\0function\0import\0absolute\0'
    symbols = b''.join(struct.pack('<IIIBBH', *s) for s in (
        (0, 0, 0, 0, 0, 0), (1, 0, 4, 0x12, 0, 1),
        (10, 0x1234, 0, 0x10, 0, 0), (17, 0x1000, 8, 0x11, 2, xff.SHN_ABS)))
    out = bytearray(xff.HEADER_SIZE)

    def place(blob, align=4):
        out.extend(bytes((-len(out)) % align))
        pos = len(out)
        out.extend(blob)
        return pos

    no = place(struct.pack('<6I', *offsets))
    sho = place(bytes(32 * 6))
    sao = place(struct.pack('<4I', 0, 0, 0x1234, 0x1000))
    ro = place(bytes(28 * 2))
    io = place(struct.pack('<I', 2))
    sno = place(shstrings)
    text = place(struct.pack('<II', 0x0C000000, 0x24020001))
    so = place(symbols)
    sto = place(strings)
    a = place(struct.pack('<II', 0, (2 << 8) | 4))
    b = place(struct.pack('<II', 0x0C000000, 0xDEADBEEF))
    c = place(struct.pack('<II', 4, (1 << 8) | 2))
    d = place(struct.pack('<II', 0x24020001, 0))
    for i, (kind, size, align, off) in enumerate((
        (0, 0, 0, 0), (1, 8, 4, text), (8, 0, 4, 0),
        (2, len(symbols), 4, so), (3, len(strings), 1, 0),
        (3, len(shstrings), 1, 0),
    )):
        struct.pack_into('<8I', out, sho + 32 * i, 0,
                         xff.POINTER_BASE + off if off else 0,
                         size, align, kind, int(kind == 8), 0, off)
    for i, (aa, bb) in enumerate(((a, b), (c, d))):
        struct.pack_into('<7I', out, ro + 28 * i, 9, 1, 1,
                         xff.POINTER_BASE + aa, xff.POINTER_BASE + bb, aa, bb)
    h = [0] * 28
    h[0] = int.from_bytes(b'xff2', 'little')
    h[5], h[7], h[9], h[14], h[16] = len(out), 1, 4, 2, 6
    h[20:28] = io, so, sto, sho, sao, ro, no, sno
    for slot, off in zip((8, 10, 11, 12, 13, 15, 17, 18), h[20:]):
        h[slot] = xff.POINTER_BASE + off
    struct.pack_into('<28I', out, 0, *h)
    return out


def word(blob, off, value):
    struct.pack_into('<I', blob, off, value)


def header(blob, index):
    return struct.unpack_from('<I', blob, 4 * index)[0]


def move_header_offset(blob, index, pointer_index, value):
    word(blob, index * 4, value)
    word(blob, pointer_index * 4, xff.POINTER_BASE + value)


def test_parse_and_metadata_duck_adapter():
    module = xff.parse(bytes(fixture()))
    assert module.num_symbols == 4
    assert module.symbol(1) == (1, 0, 4, 0x12, 0, 1)
    assert module.symbol_name(2) == 'import'
    assert module.symbol(2)[1] == 0x1234  # Undefined does not imply zero value.
    assert module.symbol(3)[5] == xff.SHN_ABS
    assert module.index_of('.bss') == 2
    assert module.sections[2].size == 0
    assert module.sections[2].data is None
    assert module.sections[1].offset > 0
    assert len(module.sections[1].data) == 8
    assert module.reltables[0].is_import
    assert module.reltables[0].entries == ((0, 0x204, 0x0C000000, 0xDEADBEEF),)
    assert not module.reltables[1].is_import
    metadata = Metadata.from_xff2(module)
    assert metadata.sections[1].name == '.text'
    assert metadata.symbols[1].name == 'function'
    assert metadata.reltables[0].entries[0].extra == 0xDEADBEEF


@pytest.mark.parametrize('index', [-1, 4, 100])
def test_invalid_lookup_indices(index):
    module = xff.parse(bytes(fixture()))
    with pytest.raises(IndexError):
        module.symbol(index)
    with pytest.raises(IndexError):
        module.symbol_name(index)
    with pytest.raises(KeyError):
        module.index_of('not-present')


@pytest.mark.parametrize('length', [0, 3, 4, 40, 111])
def test_truncated_header(length):
    with pytest.raises(xff.XffError, match='header'):
        xff.parse(bytes(fixture()[:length]))


@pytest.mark.parametrize('kind', ['magic', 'reserved', 'size', 'pointer', 'count', 'odd'])
def test_invalid_header(kind):
    blob = fixture()
    if kind == 'magic':
        blob[:4] = b'xff3'
    elif kind == 'reserved':
        word(blob, 4, 1)
    elif kind == 'size':
        word(blob, 20, len(blob) - 1)
    elif kind == 'pointer':
        word(blob, 32, 0)
    elif kind == 'count':
        word(blob, 36, xff.MAX_SYMBOLS + 1)
    else:
        word(blob, 56, 1)
    with pytest.raises(xff.XffError):
        xff.parse(bytes(blob))


@pytest.mark.parametrize('index,pointer', [(20, 8), (21, 10), (22, 11), (23, 12),
                                         (24, 13), (25, 15), (26, 17), (27, 18)])
def test_out_of_bounds_header_tables(index, pointer):
    blob = fixture()
    move_header_offset(blob, index, pointer, len(blob) + 16)
    with pytest.raises(xff.XffError):
        xff.parse(bytes(blob))


@pytest.mark.parametrize('kind', ['section', 'symbol', 'import', 'symbol-value', 'common'])
def test_invalid_references(kind):
    blob = fixture()
    if kind == 'section':
        word(blob, header(blob, 26) + 4, 0xFFFFFFFE)
    elif kind == 'symbol':
        word(blob, header(blob, 21) + 16, 0xFFFFFFFE)
    elif kind == 'import':
        word(blob, header(blob, 20), 99)
    elif kind == 'symbol-value':
        word(blob, header(blob, 21) + 20, 9)
    else:
        struct.pack_into('<H', blob, header(blob, 21) + 30, 0xFFF2)
    with pytest.raises(xff.XffError):
        xff.parse(bytes(blob))


@pytest.mark.parametrize('section_names', [True, False])
def test_unterminated_names(section_names):
    blob = fixture()
    if section_names:
        start = header(blob, 27)
        size = struct.unpack_from('<I', blob, header(blob, 23) + 32 * 5 + 8)[0]
        blob[start + size - 1] = 65
    else:
        start = header(blob, 22)
        size = struct.unpack_from('<I', blob, header(blob, 23) + 32 * 4 + 8)[0]
        blob[start + size - 1] = 65
    with pytest.raises(xff.XffError):
        xff.parse(bytes(blob))


def test_duplicate_section_names_rejected_but_duplicate_symbols_preserved():
    blob = fixture()
    word(blob, header(blob, 26) + 8, 1)  # .bss now also .text
    with pytest.raises(xff.XffError, match='ambiguous'):
        xff.parse(bytes(blob))
    blob = fixture()
    word(blob, header(blob, 21) + 32, 1)
    module = xff.parse(bytes(blob))
    assert module.symbol_name(1) == module.symbol_name(2) == 'function'


@pytest.mark.parametrize('kind', ['target', 'symbol', 'offset', 'unaligned', 'array',
                                 'count', 'overlap', 'classification', 'encoding'])
def test_invalid_relocations(kind):
    blob = fixture()
    ro = header(blob, 25)
    a = struct.unpack_from('<I', blob, ro + 20)[0]
    if kind == 'target':
        word(blob, ro + 8, 6)
    elif kind == 'symbol':
        word(blob, a + 4, 0xFFFF04)
    elif kind == 'offset':
        word(blob, a, 8)
    elif kind == 'unaligned':
        word(blob, a, 1)
    elif kind == 'array':
        word(blob, ro + 12, xff.POINTER_BASE + len(blob))
        word(blob, ro + 20, len(blob))
    elif kind == 'count':
        word(blob, ro + 4, xff.MAX_RELOCATIONS + 1)
    elif kind == 'overlap':
        word(blob, ro + 16, xff.POINTER_BASE + a)
        word(blob, ro + 24, a)
    elif kind == 'classification':
        word(blob, a + 4, 0x104)
    else:
        word(blob, ro, 4)  # RELA is not the supported REL encoding.
    with pytest.raises(xff.XffError):
        xff.parse(bytes(blob))


def test_bss_size_cap_and_no_allocation():
    blob = fixture()
    size_off = header(blob, 23) + 32 * 2 + 8
    word(blob, size_off, xff.MAX_SECTION_SIZE)
    module = xff.parse(bytes(blob))
    assert module.sections[2].size == xff.MAX_SECTION_SIZE
    assert module.sections[2].data is None
    word(blob, size_off, 0xFFFFFFFF)
    with pytest.raises(xff.XffError, match='size limit'):
        xff.parse(bytes(blob))


def test_overlapping_sections():
    blob = fixture()
    sho = header(blob, 23)
    off = header(blob, 21)
    word(blob, sho + 32 + 4, xff.POINTER_BASE + off)
    word(blob, sho + 32 + 28, off)
    with pytest.raises(xff.XffError, match='overlapping'):
        xff.parse(bytes(blob))


def test_empty_relocation_arrays_may_share_offsets():
    blob = fixture()
    ro = header(blob, 25)
    for t in range(2):
        word(blob, ro + 28 * t + 4, 0)
        for pointer, offset in ((12, 20), (16, 24)):
            word(blob, ro + 28 * t + pointer, xff.POINTER_BASE + len(blob))
            word(blob, ro + 28 * t + offset, len(blob))
    assert all(not t.entries for t in xff.parse(bytes(blob)).reltables)


def test_all_truncated_prefixes_fail_cleanly():
    original = fixture()
    for length in range(xff.HEADER_SIZE, len(original)):
        blob = original[:length]
        word(blob, 20, length)  # Exercise tables, not just the file-size check.
        with pytest.raises(xff.XffError):
            xff.parse(bytes(blob))


def test_name_limits(monkeypatch):
    monkeypatch.setattr(xff, 'MAX_NAME_SIZE', 7)
    with pytest.raises(xff.XffError, match='oversized'):
        xff.parse(bytes(fixture()))
    monkeypatch.setattr(xff, 'MAX_NAME_SIZE', 4096)
    monkeypatch.setattr(xff, 'MAX_TOTAL_NAME_SIZE', 10)
    with pytest.raises(xff.XffError, match='budget'):
        xff.parse(bytes(fixture()))


def test_total_section_size_limit(monkeypatch):
    monkeypatch.setattr(xff, 'MAX_TOTAL_SECTION_SIZE', 8)
    with pytest.raises(xff.XffError, match='size limit'):
        xff.parse(bytes(fixture()))


@pytest.mark.parametrize('value', [1, 8, 0xFFFFFFFF])
def test_invalid_entry(value):
    blob = fixture()
    word(blob, 19 * 4, value)
    with pytest.raises(xff.XffError, match='entry point'):
        xff.parse(bytes(blob))


def test_unstored_metadata_section_and_latin1_names():
    blob = fixture()
    sho = header(blob, 23)
    # Known .reginfo-style unstored metadata has a size but no bytes.
    word(blob, sho + 32 * 2 + 16, 0x70000006)
    word(blob, sho + 32 * 2 + 20, 0)
    word(blob, sho + 32 * 2 + 8, 24)
    blob[header(blob, 22) + 1] = 0xFF
    module = xff.parse(bytes(blob))
    assert module.sections[2].data is None
    assert module.symbol_name(1) == '\xffunction'


def test_empty_rela_and_debug_sections():
    blob = fixture()
    sho = header(blob, 23)
    # Empty RELA placeholders have no arrays and require no RELA decoding.
    word(blob, sho + 32 * 2 + 16, 4)
    word(blob, sho + 32 * 2 + 20, 0)
    assert xff.parse(bytes(blob)).sections[2].data is None
    word(blob, sho + 32 * 2 + 8, 12)
    with pytest.raises(xff.XffError, match='nonempty RELA'):
        xff.parse(bytes(blob))
    # Empty PROGBITS may have the same offset as the next stored section.
    word(blob, sho + 32 * 2 + 8, 0)
    word(blob, sho + 32 * 2 + 16, 1)
    word(blob, sho + 32 * 2 + 12, 1)
    off = header(blob, 21)
    word(blob, sho + 32 * 2 + 4, xff.POINTER_BASE + off)
    word(blob, sho + 32 * 2 + 28, off)
    assert xff.parse(bytes(blob)).sections[2].data == b''


def orphan_marker_fixture():
    blob = fixture()
    # Repurpose the otherwise absolute symbol as KERNEL's empty section marker.
    struct.pack_into('<IIIBBH', blob, header(blob, 21) + 48, 0, 0, 0, 3, 0, 6)
    word(blob, header(blob, 24) + 12, 0)
    return blob


def test_unreferenced_kernel_section_marker_is_preserved():
    module = xff.parse(bytes(orphan_marker_fixture()))
    assert module.symbol(3) == (0, 0, 0, 3, 0, len(module.sections))
    assert Metadata.from_xff2(module).symbols[3].shndx == len(module.sections)


@pytest.mark.parametrize('field,value', [(0, 1), (4, 1), (8, 1), (12, 0x13),
                                         (13, 1), (14, 7)])
def test_other_dangling_section_symbols_rejected(field, value):
    blob = orphan_marker_fixture()
    offset = header(blob, 21) + 48 + field
    if field in (12, 13):
        blob[offset] = value
    elif field == 14:
        struct.pack_into('<H', blob, offset, value)
    else:
        word(blob, offset, value)
    if field == 4:
        word(blob, header(blob, 24) + 12, value)
    with pytest.raises(xff.XffError, match='unsupported index'):
        xff.parse(bytes(blob))


def test_relocation_cannot_reference_orphan_section_marker():
    blob = orphan_marker_fixture()
    local_table = header(blob, 25) + 28
    a = struct.unpack_from('<I', blob, local_table + 20)[0]
    word(blob, a + 4, (3 << 8) | 2)
    with pytest.raises(xff.XffError, match='relocation symbol'):
        xff.parse(bytes(blob))
