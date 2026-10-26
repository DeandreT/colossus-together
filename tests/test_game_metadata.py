import struct
from dataclasses import replace

import pytest

from game import ConstructorFamily as Family
from game import MetadataError, Part, Snapshot, classify_name
from injection.records import Kind, Record


class Memory:
    def __init__(self, size=0x10000):
        self.data = bytearray(size)
        self.reads = []

    def read(self, address, size):
        self.reads.append((address, size))
        return self.data[address : address + size]

    def word(self, address, value):
        struct.pack_into("<I", self.data, address, value)


@pytest.fixture
def scene():
    m = Memory()
    s = Snapshot(m.read, quiescent=True, undefined_symbol=0xDEADBEEF)
    p1, obj, definition = 0x1000, 0x2000, 0x3000
    m.data[p1 + 8] = 9
    m.data[obj + 8] = 11
    m.word(obj + 0x90 + 0x144, 0x4000)
    m.word(0x4000, 0x5000)
    m.word(0x5000 + 0x20, 0x6000)
    m.word(0x6000, 0x004F4D4E)
    m.word(0x6004, 3)
    m.word(0x6070, 0x7000)
    name = b"player_A_mantle_LV16.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    m.word(obj + 0x150, p1)
    m.word(obj + 0x180, 1)
    m.word(obj + 0x90 + 0x194, p1)
    m.word(p1 + 0x90 + 0x144, 0x4100)
    m.word(0x4100, 0x5100)
    m.word(0x5120, 0x6100)
    m.word(0x6100, 0x004F4D4E)
    m.word(0x6104, 3)
    m.word(0x6170, 0x7100)
    dummy_name = b"player_A_dummy.nmo\0"
    m.data[0x7100 : 0x7100 + len(dummy_name)] = dummy_name
    # Non-zero index forces packed upper bits to differ from distance.
    m.word(definition + 4, (3 << 18) | 0x104)
    m.word(0x2F00, 0x8000)
    m.word(0x8008, 0x8100)
    m.word(0x810C, 0x10)
    m.word(0x8010, 0x8200)
    m.word(0x8238, 0x5000)
    gp = bytearray(0x40)
    struct.pack_into("<I", gp, 0, p1)
    struct.pack_into("<I", gp, 0x30, 1)
    record = Record(
        1,
        Kind.ALIAS_LAYOUT,
        0,
        obj,
        (0, definition, 0, 0, p1, 0, 0, 0),
        0xFFFF0000,
        bytes(0x3C),
        bytes(gp),
    )
    return m, s, record


@pytest.mark.parametrize(
    "part,suffix", [(Part.BODY, ""), (Part.MANTLE, "_mantle"), (Part.HEAD, "_head")]
)
@pytest.mark.parametrize("level", [None, 1, 4, 8, 12, 16])
def test_exact_supported_names(part, suffix, level):
    name = "player_A" + suffix + (f"_LV{level}" if level else "") + ".nmo"
    model = classify_name(name)
    assert (model.part, model.level) == (part, level)


@pytest.mark.parametrize(
    "name",
    [
        "player_A_dummy.nmo",
        "player_A_death.nmo",
        "player_A_guard.nmo",
        "player_A_shaman.nmo",
        "player_A_swordcase.nmo",
        "player_A_LV2.nmo",
        "player_A_head_LV20.nmo",
        "dir/player_A.nmo",
        "PLAYER_A.nmo",
        "player_A.nmo.bak",
        "player_A.nmo\0",
        "player_A_LV01.nmo",
    ],
)
def test_excluded_names(name):
    with pytest.raises(MetadataError):
        classify_name(name)


def test_live_and_capture_owned_copies(scene):
    m, s, record = scene
    raw_parameters, raw_gp = bytearray(record.parameters), bytearray(record.gp_bytes)
    record = replace(record, parameters=raw_parameters, gp_bytes=raw_gp)
    visual = s.captured(record, canonical_p1=0x1000)
    assert visual.model.part == Part.MANTLE
    assert visual.parent_p1 == visual.skeleton_source == 0x1000
    assert visual.definition_ptr == 0x3000
    raw_parameters[0] = raw_gp[0] = 99
    assert visual.parameters[0] == visual.gp_bytes[0] == 0
    assert all(address < 0x10000 for address, _ in m.reads)


@pytest.mark.parametrize(
    "address,value",
    [
        (0x2180, 2),
        (0x2150, 0x1100),
        (0x2224, 0x1100),
        (0x4000, 0),
        (0x5020, 0x1FFFFFC),
        (0x6000, 0),
        (0x6004, 4),
        (0x6070, 0),
        (0x6070, 0x2000000),
        (0x4000, 0x5001),
    ],
)
def test_bad_chain_and_ownership(scene, address, value):
    m, s, _ = scene
    m.word(address, value)
    with pytest.raises(MetadataError):
        s.live(0x2000, definition_ptr=0x3000, family=Family.ALIAS, canonical_p1=0x1000)


@pytest.mark.parametrize("raw", [b"x" * 128, b"player_A_\xff.nmo\0", b"\0"])
def test_malformed_names(scene, raw):
    m, s, _ = scene
    m.data[0x7000:0x7080] = raw.ljust(128, b"x")
    with pytest.raises(MetadataError):
        s.model_from_resource(0x5000)


def test_head_definition_kind_is_not_isys_type(scene):
    m, s, r = scene
    name = b"player_A_head.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    m.data[0x2008] = 9
    m.word(0x3000, 11)  # Character-definition kind is NOT object ISYS type.
    m.word(0x3014, (3 << 18) | 0x114)
    r = replace(r, kind=Kind.SCRIPT_CHAR)
    assert s.captured(r, canonical_p1=0x1000).model.part == Part.HEAD
    m.data[0x2008] = 11
    with pytest.raises(MetadataError):
        s.captured(r, canonical_p1=0x1000)


def test_body_is_separate_alias_of_canonical_dummy(scene):
    m, s, record = scene
    name = b"player_A.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    visual = s.captured(record, canonical_p1=0x1000)
    assert visual.model.part == Part.BODY
    assert visual.family == Family.ALIAS
    assert visual.object_ptr == 0x2000
    assert visual.parent_p1 == visual.skeleton_source == 0x1000
    with pytest.raises(MetadataError, match="unsupported model basename"):
        s.model_from_resource(0x5100)
    m.data[0x2008] = 9
    with pytest.raises(MetadataError):
        s.live(
            0x2000, definition_ptr=0x3000, family=Family.CHARACTER, canonical_p1=0x1000
        )


@pytest.mark.parametrize(
    "address,value",
    [(0x2150, 0x1100), (0x2180, 2), (0x2224, 0x1100)],
)
def test_body_requires_live_parent_and_skeleton(scene, address, value):
    m, s, record = scene
    name = b"player_A.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    m.word(address, value)
    with pytest.raises(MetadataError):
        s.captured(record, canonical_p1=0x1000)


@pytest.mark.parametrize("fault", ["parent", "source", "missing_gp"])
def test_body_requires_captured_parent_and_alias_source(scene, fault):
    m, s, record = scene
    name = b"player_A.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    if fault == "parent":
        gp = bytearray(record.gp_bytes)
        struct.pack_into("<I", gp, 0, 0x1100)
        record = replace(record, gp_bytes=bytes(gp))
    elif fault == "source":
        record = replace(record, arguments=(0, 0x3000, 0, 0, 0x1100, 0, 0, 0))
    else:
        record = replace(record, gp_ptr=0, gp_bytes=b"")
    with pytest.raises(MetadataError):
        s.captured(record, canonical_p1=0x1000)


def test_body_cannot_be_canonical_p1(scene):
    m, s, _ = scene
    name = b"player_A.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    m.data[0x1000:0x1300] = m.data[0x2000:0x2300]
    with pytest.raises(MetadataError):
        s.live(0x1000, definition_ptr=0x3000, family=Family.ALIAS, canonical_p1=0x1000)


def test_body_alias_real_address_layout(scene):
    original, _, record = scene
    m = Memory(32 * 1024 * 1024)
    m.data[: len(original.data)] = original.data
    main, body = 0x1DDDDE0, 0x1E00D00
    m.data[main : main + 0x300] = original.data[0x1000:0x1300]
    m.data[body : body + 0x300] = original.data[0x2000:0x2300]
    name = b"player_A.nmo\0"
    m.data[0x7000 : 0x7000 + len(name)] = name
    m.word(body + 0x150, main)
    m.word(body + 0x90 + 0x194, main)
    gp = bytearray(record.gp_bytes)
    struct.pack_into("<I", gp, 0, main)
    record = replace(
        record,
        object_ptr=body,
        arguments=(0, 0x3000, 0, 0, main, 0, 0, 0),
        gp_bytes=bytes(gp),
    )
    s = Snapshot(m.read, quiescent=True, undefined_symbol=0xDEADBEEF)
    visual = s.captured(record, canonical_p1=main)
    assert visual.object_ptr == body != main
    assert visual.family == Family.ALIAS
    assert visual.model.part == Part.BODY
    assert visual.parent_p1 == visual.skeleton_source == main


@pytest.mark.parametrize(
    "address,value",
    [
        (0x2F00, 0),
        (0x2F00, 0xDEADBEEF),
        (0x2F00, 0x8001),
        (0x8008, 0),
        (0x810C, 0),
        (0x810C, 10),
        (0x810C, 0xFFFFFFFC),
        (0x8010, 0x1FFFFFC),
        (0x8238, 0),
        (0x3004, (0xFFF << 18) | 0x3FFFF),
    ],
)
def test_bad_packed_reference(scene, address, value):
    m, s, _ = scene
    m.word(address, value)
    with pytest.raises(MetadataError):
        s.definition_model(0x3000, family=Family.ALIAS)


def test_packed_mask_and_index_carry(scene):
    _, s, _ = scene
    assert s.definition_model(0x3000, family=Family.ALIAS).level == 16


@pytest.mark.parametrize(
    "changes",
    [
        {"flags": 1},
        {"gp_bytes": b""},
        {"parameters": b""},
        {"kind": Kind.DELETE_REQUEST},
        {"object_ptr": 0},
        {"gp_ptr": 0},
        {"arguments": (0, 0x3000, 0, 0, 0x1100, 0, 0, 0)},
    ],
)
def test_bad_capture(scene, changes):
    _, s, r = scene
    with pytest.raises(MetadataError):
        s.captured(replace(r, **changes), canonical_p1=0x1000)


@pytest.mark.parametrize("offset,value", [(0, 0x1100), (0x30, 2)])
def test_wrong_captured_parent(scene, offset, value):
    _, s, r = scene
    gp = bytearray(r.gp_bytes)
    struct.pack_into("<I", gp, offset, value)
    with pytest.raises(MetadataError):
        s.captured(replace(r, gp_bytes=gp), canonical_p1=0x1000)


def test_live_and_definition_must_agree(scene):
    m, s, r = scene
    m.word(0x8238, 0x5100)
    m.word(0x5120, 0x6100)
    m.word(0x6100, 0x004F4D4E)
    m.word(0x6104, 3)
    m.word(0x6170, 0x7100)
    name = b"player_A_mantle_LV8.nmo\0"
    m.data[0x7100 : 0x7100 + len(name)] = name
    with pytest.raises(MetadataError, match="model mismatch"):
        s.captured(r, canonical_p1=0x1000)


def test_resource_pointer_is_not_header_pointer(scene):
    _, s, _ = scene
    with pytest.raises(MetadataError):
        s.model_from_resource(0x6000)


@pytest.mark.parametrize(
    "address,size,alignment",
    [
        (0, 4, 4),
        (-4, 4, 4),
        (0x1FFFFFC, 8, 4),
        (3, 4, 4),
        (0x80000000, 4, 4),
        (True, 4, 4),
        (4, 0, 4),
        (4, 4, 0),
    ],
)
def test_ranges(address, size, alignment):
    with pytest.raises(MetadataError):
        Snapshot.checked(address, size, alignment)


def test_quiescence_and_short_reads():
    with pytest.raises(MetadataError):
        Snapshot(lambda a, n: bytes(n), quiescent=False, undefined_symbol=0)
    s = Snapshot(lambda a, n: b"", quiescent=True, undefined_symbol=0)
    with pytest.raises(MetadataError):
        s.u32(4)


def group_setup(scene):
    m, s, _ = scene
    struct.pack_into("<H", m.data, 0x9000, 1)
    m.word(0xA018, 0x1000)
    struct.pack_into("<H", m.data, 0xA026, 2)
    m.word(0xA030, 0x2000)
    struct.pack_into("<H", m.data, 0xA03E, 0)
    return m, s


def walk(s, **kwargs):
    return s.group(
        0x9000,
        node_pool=0xA000,
        node_count=3,
        deleted_flags_offset=0xC,
        deleted_mask=1,
        **kwargs,
    )


def test_group_skips_deleted_without_mutating(scene):
    m, s = group_setup(scene)
    m.word(0x100C, 1)
    before = bytes(m.data)
    assert walk(s) == (0x2000,)
    assert bytes(m.data) == before


@pytest.mark.parametrize("next_index", [1, 2, 3, 65535])
def test_group_cycles_and_stale_index(scene, next_index):
    m, s = group_setup(scene)
    struct.pack_into("<H", m.data, 0xA03E, next_index)
    with pytest.raises(MetadataError):
        walk(s)


def test_group_cap_and_stale_object(scene):
    m, s = group_setup(scene)
    with pytest.raises(MetadataError):
        walk(s, max_nodes=1)
    m.word(0xA030, 0)
    with pytest.raises(MetadataError):
        walk(s)
