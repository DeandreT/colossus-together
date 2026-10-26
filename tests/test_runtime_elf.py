"""All object bytes here are synthetic, not derived from game assets."""

import struct

import pytest

from runtime.elf import LinkError, link_object


def object_bytes(
    words=(0,),
    relocs=(),
    *,
    flags=0x20924001,
    external=True,
    machine=8,
    kind=1,
    text_align=4,
    bss_size=8,
):
    names = [
        "",
        ".text",
        ".data",
        ".bss",
        ".shstrtab",
        ".strtab",
        ".symtab",
        ".rel.text",
    ]
    shstrings = b"\0"
    name_offsets = [0]
    for name in names[1:]:
        name_offsets.append(len(shstrings))
        shstrings += name.encode() + b"\0"
    strings = b"\0entry\0external\0absolute\0"
    def symbol(n, v, s, info, sec):
        return struct.pack("<IIIBBH", n, v, s, info, 0, sec)
    symbols = (
        bytes(16)
        + symbol(0, 0, 0, 3, 1)
        + symbol(1, 0, 4, 0x12, 1)
        + symbol(7, 0, 0, 0x10, 0 if external else 0xFFF1)
        + symbol(16, 0x4560, 0, 0x10, 0xFFF1)
    )
    text = struct.pack(f"<{len(words)}I", *words)
    relocation_bytes = b"".join(
        struct.pack("<II", off, (sym << 8) | typ) for off, sym, typ in relocs
    )
    # name,type,flags,addr,offset,size,link,info,alignment,entry size
    payloads = [
        b"",
        text,
        b"\x11\x22\x33\x44",
        b"",
        shstrings,
        strings,
        symbols,
        relocation_bytes,
    ]
    types = [0, 1, 1, 8, 3, 3, 2, 9]
    aligns = [0, text_align, 4, 8, 1, 1, 4, 4]
    image = bytearray(52)
    sections = []
    for i, payload in enumerate(payloads):
        if not i:
            sections.append((0,) * 10)
            continue
        while len(image) % max(1, aligns[i]):
            image.append(0)
        offset = len(image)
        image.extend(payload)
        sections.append(
            (
                name_offsets[i],
                types[i],
                6 if i == 1 else 3 if i in (2, 3) else 0,
                0,
                offset,
                bss_size if i == 3 else len(payload),
                5 if i == 6 else 6 if i == 7 else 0,
                2 if i == 6 else 1 if i == 7 else 0,
                aligns[i],
                16 if i == 6 else 8 if i == 7 else 0,
            )
        )
    while len(image) % 4:
        image.append(0)
    shoff = len(image)
    image.extend(b"".join(struct.pack("<10I", *sec) for sec in sections))
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    struct.pack_into(
        "<16sHHIIIIIHHHHHH",
        image,
        0,
        ident,
        kind,
        machine,
        1,
        0,
        0,
        shoff,
        flags,
        52,
        0,
        0,
        40,
        len(sections),
        4,
    )
    return bytes(image)


PLACEMENTS = {".text": 0x1000, ".data": 0x2000, ".bss": 0x3000}


def link(blob, externals=None, **kwargs):
    return link_object(
        blob,
        PLACEMENTS,
        {"external": 0x12340000} if externals is None else externals,
        **kwargs,
    )


def words(result):
    data = result.payloads[0].data
    return struct.unpack(f"<{len(data) // 4}I", data)


@pytest.mark.parametrize("flags", [0x20924001, 0x70001001])
def test_sections_exports_abi_containers(flags):
    result = link(object_bytes(flags=flags))
    assert [(p.section, p.address) for p in result.payloads] == list(PLACEMENTS.items())
    assert result.payloads[1].data == b"\x11\x22\x33\x44"
    assert result.payloads[2].data == bytes(8)
    assert result.exports == {"entry": 0x1000, "absolute": 0x4560}


def test_word_relocations_defined_section_absolute_external():
    result = link(
        object_bytes(
            (4, 8, 12, 0xFFFFFFFC), [(0, 1, 2), (4, 2, 2), (8, 4, 2), (12, 3, 2)]
        )
    )
    assert words(result) == (0x1004, 0x1008, 0x456C, 0x1233FFFC)


def test_signed_low_carry_multiple_highs():
    result = link(
        object_bytes(
            (0x3C010000, 0x3C020001, 0x24218000), [(0, 3, 5), (4, 3, 5), (8, 3, 6)]
        )
    )
    assert words(result) == (0x3C011234, 0x3C021235, 0x24218000)


def test_carry_when_symbol_low_crosses_sign_boundary():
    result = link(
        object_bytes((0x3C010000, 0x24210010), [(0, 3, 5), (4, 3, 6)]),
        {"external": 0x12347FF0},
    )
    assert words(result) == (0x3C011235, 0x24218000)


def test_negative_high_addend():
    result = link(object_bytes((0x3C01FFFF, 0x2421FFFC), [(0, 3, 5), (4, 3, 6)]))
    assert words(result) == (0x3C011233, 0x2421FFFC)


def test_low_without_high():
    assert words(link(object_bytes((0x2421FFFF,), [(0, 3, 6)]))) == (0x2421FFFF,)


def test_jump():
    result = link(object_bytes((0x0C000001,), [(0, 3, 4)]), {"external": 0x1400})
    assert words(result) == (0x0C000501,)


@pytest.mark.parametrize("address", [0x10001400, 0x1401])
def test_jump_region_alignment(address):
    with pytest.raises(LinkError, match="MIPS26"):
        link(object_bytes((0x0C000000,), [(0, 3, 4)]), {"external": address})


@pytest.mark.parametrize(
    "relocs,match",
    [
        ([(0, 3, 5)], "unpaired"),
        ([(0, 3, 9)], "unsupported MIPS"),
        ([(0, 99, 2)], "symbol"),
        ([(4, 3, 2)], "range"),
        ([(1, 3, 2)], "unaligned"),
        ([(0, 3, 2), (0, 3, 2)], "overlapping"),
    ],
)
def test_relocation_rejections(relocs, match):
    with pytest.raises(LinkError, match=match):
        link(object_bytes(relocs=relocs))


def test_unresolved():
    with pytest.raises(LinkError, match="unresolved"):
        link(object_bytes(), {})


@pytest.mark.parametrize(
    "placement",
    [
        {".text": 0x2000, ".data": 0x2000, ".bss": 0x3000},
        PLACEMENTS | {".bss": 0x2000},
        PLACEMENTS | {".text": 0x1001},
        PLACEMENTS | {".bss": 0xFFFFFFF8},
        {".text": 0x1000},
        PLACEMENTS | {".unused": 0x4000},
        PLACEMENTS | {".text": -4},
    ],
)
def test_placement_guards(placement):
    with pytest.raises(LinkError):
        link_object(object_bytes(bss_size=16), placement, {"external": 0})


@pytest.mark.parametrize("options", [{"machine": 3}, {"kind": 2}])
def test_header_identity(options):
    with pytest.raises(LinkError, match="ELF32"):
        link(object_bytes(**options))


def test_wrong_endianness_and_truncation():
    blob = bytearray(object_bytes())
    blob[5] = 2
    with pytest.raises(LinkError):
        link(bytes(blob))
    for length in (0, 20, 51, 53, len(blob) - 1):
        with pytest.raises(LinkError):
            link(object_bytes()[:length])


def test_output_limit():
    with pytest.raises(LinkError, match="output exceeds"):
        link(object_bytes(bss_size=128), max_output=64)


def change_section(blob, index, field, value):
    blob = bytearray(blob)
    shoff = struct.unpack_from("<I", blob, 32)[0]
    struct.pack_into("<I", blob, shoff + index * 40 + field * 4, value)
    return bytes(blob)


@pytest.mark.parametrize(
    "index,field,value",
    [
        (1, 8, 3),
        (1, 4, 0xFFFFFFF0),
        (6, 9, 8),
        (6, 6, 1),
        (7, 1, 4),
        (7, 9, 12),
        (7, 7, 99),
        (1, 1, 7),
    ],
)
def test_malformed_sections(index, field, value):
    with pytest.raises(LinkError):
        link(change_section(object_bytes(relocs=[(0, 3, 2)]), index, field, value))


def test_symbol_bounds_and_common():
    original = object_bytes()
    shoff = struct.unpack_from("<I", original, 32)[0]
    symoff = struct.unpack_from("<I", original, shoff + 6 * 40 + 16)[0]
    for offset, fmt, value in [
        (symoff + 32 + 4, "I", 0x100),
        (symoff + 48 + 14, "H", 0xFFF2),
    ]:
        blob = bytearray(original)
        struct.pack_into("<" + fmt, blob, offset, value)
        with pytest.raises(LinkError):
            link(bytes(blob))
