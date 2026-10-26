"""Offline C classifier tests. Never import PINE or write a game/state image.

All memory and resources are synthetic. Compiler output stays in pytest temp.
"""

import ctypes as C
import itertools
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UNKNOWN, SAFE, RETIRE = 0, 1, 2
U = C.c_uint32
READ32 = C.CFUNCTYPE(C.c_int, C.c_void_p, U, C.POINTER(U))
READ8 = C.CFUNCTYPE(C.c_int, C.c_void_p, U, C.POINTER(C.c_uint8))


class Header(C.Structure):
    _fields_ = [("object", U), ("descriptor", U)]


class Config(C.Structure):
    _fields_ = [
        ("user", C.c_void_p),
        ("read32", READ32),
        ("read8", READ8),
        ("headers", C.POINTER(Header)),
    ] + [
        (n, U)
        for n in (
            "header_count",
            "list_limit",
            "generation",
            "generation_address",
            "quiescent",
            "source_guards_verified",
            "language",
            "language_address",
            "undefined_symbol",
            "stage_descriptor",
            "segment_counters",
            "segment_capacity",
            "texture_table",
            "texture_capacity",
        )
    ]


class Definition(C.Structure):
    _fields_ = [
        (n, U) for n in ("address", "family", "generation", "constructor_verified")
    ]


class ExtraBinding(C.Structure):
    _fields_ = [("proof", Definition)] + [
        (n, U)
        for n in (
            "definition_owner",
            "model_owner",
            "model",
            "model_raw",
            "model_header",
        )
    ]


class Node(C.Structure):
    _fields_ = [
        (n, U)
        for n in (
            "object",
            "raw",
            "header",
            "descriptor",
            "flags",
            "object_flags",
            "header_raw",
            "header_flags",
            "type",
            "count",
            "base",
            "stride",
            "reference_count",
            "references",
            "next",
            "reference_fingerprint",
            "decrements",
            "color",
        )
    ]


class Frame(C.Structure):
    _fields_ = [("node", U), ("next_reference", U)]


class Workspace(C.Structure):
    _fields_ = (
        [("nodes", C.POINTER(Node)), ("frames", C.POINTER(Frame))]
        + [
            (n, U)
            for n in (
                "capacity",
                "frame_capacity",
                "count",
                "generation",
                "language",
                "complete",
            )
        ]
        + [
            (n, U * 4)
            for n in (
                "definition_owners",
                "model_owners",
                "definitions",
                "models",
                "families",
                "model_raw",
                "model_headers",
            )
        ]
    ) + [("extra_count", U), ("extras", ExtraBinding * 32)]


def workspace(capacity=512):
    ns, fs = (Node * capacity)(), (Frame * capacity)()
    w = Workspace(nodes=ns, frames=fs, capacity=capacity, frame_capacity=capacity)
    w._keep = ns, fs
    return w


@pytest.fixture(scope="session")
def lib(tmp_path_factory):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler unavailable")
    out = tmp_path_factory.mktemp("resource-safety") / "classifier.so"
    subprocess.run(
        [
            cc,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wconversion",
            "-O2",
            "-shared",
            "-fPIC",
            str(ROOT / "resource_safety/resource_safety.c"),
            "-o",
            str(out),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    dll = C.CDLL(str(out))
    dll.rs_build_protected.argtypes = [
        C.POINTER(Config),
        C.POINTER(Definition),
        C.POINTER(Workspace),
    ]
    dll.rs_build_protected.restype = C.c_int
    dll.rs_extend_protected.argtypes = [
        C.POINTER(Config),
        C.POINTER(Definition),
        U,
        C.POINTER(Workspace),
    ]
    dll.rs_extend_protected.restype = C.c_int
    dll.rs_classify.argtypes = [
        C.POINTER(Config),
        U,
        C.POINTER(Workspace),
        C.POINTER(Workspace),
    ]
    dll.rs_classify.restype = C.c_int
    return dll


class Memory:
    def __init__(self, frozen=None):
        self.frozen = frozen
        self.overlay = {}
        self.cursor = 0x80000
        self.fail_address = None
        self.after_read = None
        self.read32_count = 0
        self.r32 = READ32(self.read32)
        self.r8 = READ8(self.read8)

    def alloc(self, size=0x100):
        a = self.cursor
        self.cursor += (size + 15) & ~15
        return a

    def get8(self, a):
        if a in self.overlay:
            return self.overlay[a]
        return self.frozen[a] if self.frozen is not None else 0

    def get(self, a):
        return sum(self.get8(a + i) << (8 * i) for i in range(4))

    def put8(self, a, v):
        self.overlay[a] = v & 255

    def put(self, a, v):
        for i in range(4):
            self.put8(a + i, v >> (8 * i))

    def read32(self, _, a, out):
        self.read32_count += 1
        if a == self.fail_address or a < 0x80000 or a > 0x1FFFFFC or a & 3:
            return 0
        out[0] = self.get(a)
        if self.after_read:
            self.after_read(a)
        return 1

    def read8(self, _, a, out):
        if a == self.fail_address or a < 0x80000 or a >= 0x2000000:
            return 0
        out[0] = self.get8(a)
        return 1


class Fixture:
    def __init__(self, lib):
        self.lib, self.m = lib, Memory()
        self.headers = []
        self.generation = self.m.alloc()
        self.language = self.m.alloc()
        self.m.put(self.generation, 19)
        self.m.put(self.language, 1)
        self.defs = (Definition * 4)()
        self.roots, self.models = [], []
        for i in range(4):
            model = self.make_node(stride=16, refs=20)
            resource, nmo = self.m.alloc(), self.m.alloc()
            self.m.put(resource, self.m.alloc())
            self.m.put(resource + 8, 1)
            self.m.put(resource + 0x20, nmo)
            self.m.put(nmo, 0x004F4D4E)
            self.m.put(nmo + 4, 3)
            self.m.put(self.base(model) + 8, resource)
            slot = self.m.alloc(12)
            root = self.make_node(stride=0x40, refs=1)
            family = 0 if i in (0, 3) else 1
            d = self.base(root)
            field = d + (4 if family else 0x14)
            self.m.put(slot, self.desc(model))
            self.m.put(field, field - slot)
            self.edges(root, [(model, 0)])
            self.defs[i] = Definition(d, family, 19, 1)
            self.roots.append(root)
            self.models.append(model)
        self.stage = self.make_node(stride=20, records=32, refs=1)
        self.counters, self.textures, self.request = (
            self.m.alloc(32),
            self.m.alloc(32),
            self.m.alloc(),
        )
        for i in range(32):
            self.m.put8(self.counters + i, 1)
        typ = self.m.get(self.desc(self.stage) + 8)
        offsets = self.m.alloc(8)
        self.m.put(offsets, 4)
        self.m.put(offsets + 4, 8)
        self.m.put(typ + 16, 2)
        self.m.put(typ + 20, offsets)
        self.set_segment(0, [self.roots[0]])
        self.refresh_config()
        self.p, self.r = workspace(), workspace(4096)

    def desc(self, o):
        return self.m.get(o + 0x38)

    def base(self, o):
        return self.m.get(self.desc(o) + 16)

    def make_node(self, stride=16, records=1, refs=10):
        h, typ, o, d, base = [
            self.m.alloc(s) for s in (0x60, 0x40, 0x60, 0x40, stride * records)
        ]
        self.headers.append((h, typ))
        self.m.put(h, self.m.alloc())
        self.m.put(h + 8, 4)
        self.m.put(h + 0x38, typ)
        self.m.put(h + 0x40, o)
        self.m.put(typ + 12, stride)
        self.m.put(o, self.m.alloc())
        self.m.put(o + 8, 5)
        self.m.put(o + 0x38, d)
        self.m.put(o + 0x3C, h)
        self.m.put(o + 0x44, refs << 20)
        self.m.put(d + 8, typ)
        self.m.put(d + 12, records)
        self.m.put(d + 16, base)
        self.m.put(d + 20, o)
        return o

    def edges(self, o, entries):
        a = self.m.alloc(max(12, len(entries) * 12))
        self.m.put(self.desc(o) + 24, len(entries))
        self.m.put(self.desc(o) + 28, a)
        for i, (target, flags) in enumerate(entries):
            self.m.put(a + i * 12, self.desc(target) if target else 0)
            self.m.put(a + i * 12 + 8, flags)
        return a

    def set_segment(self, seg, roots):
        a = self.base(self.stage) + 20 * seg
        for i, o in enumerate(roots):
            field = a + 4 + i * 4
            # A forward allocation is not a representable backward reference;
            # reuse a reserved header word before all stage records.
            slot = self.desc(self.stage) + 0x28 + i * 12
            self.m.put(slot, self.desc(o))
            self.m.put(slot + 8, 0)
            self.m.put(field, field - slot)

    def refresh_config(self):
        self.hs = (Header * len(self.headers))(*(Header(*h) for h in self.headers))
        self.c = Config(
            read32=self.m.r32,
            read8=self.m.r8,
            headers=self.hs,
            header_count=len(self.hs),
            list_limit=4096,
            generation=19,
            generation_address=self.generation,
            quiescent=1,
            source_guards_verified=1,
            language=1,
            language_address=self.language,
            undefined_symbol=0xFFFFFFFC,
            stage_descriptor=self.desc(self.stage),
            segment_counters=self.counters,
            segment_capacity=32,
            texture_table=self.textures,
            texture_capacity=4,
        )

    def build(self):
        self.refresh_config()
        return self.lib.rs_build_protected(C.byref(self.c), self.defs, C.byref(self.p))

    def classify(self, op=1, seg=0, h=None):
        self.m.put(self.request, op)
        self.m.put(self.request + 8, self.desc(self.stage) if h is None else h)
        self.m.put(self.request + 12, seg)
        return self.lib.rs_classify(
            C.byref(self.c), self.request, C.byref(self.p), C.byref(self.r)
        )


@pytest.fixture
def f(lib):
    return Fixture(lib)


def test_ref1_retires_ref2_safe(f):
    assert f.build() == SAFE
    assert f.classify() == RETIRE
    f.m.put(f.roots[0] + 0x44, 2 << 20)
    assert f.build() == SAFE
    assert f.classify() == SAFE


def test_segment_counter_fast_path_and_disjoint(f):
    assert f.build() == SAFE
    f.m.put8(f.counters, 2)
    assert f.classify() == SAFE
    f.m.put8(f.counters, 0)
    assert f.classify() == UNKNOWN
    f.m.put8(f.counters, 1)
    unrelated = f.make_node(refs=1)
    f.set_segment(0, [unrelated])
    assert f.build() == SAFE
    assert f.classify() == SAFE


def test_exact_edge_multiplicity_and_diamond(f):
    a, b = f.make_node(), f.make_node()
    leaf = f.models[0]
    f.edges(f.roots[0], [(a, 0), (b, 0)])
    f.edges(a, [(leaf, 0), (leaf, 0)])
    f.edges(b, [(leaf, 0)])
    f.m.put(f.roots[0] + 0x44, 20 << 20)
    f.m.put(leaf + 0x44, 4 << 20)  # self + three incoming edges
    assert f.build() == SAFE
    assert f.classify() == RETIRE
    n = next(n for n in f.r.nodes[: f.r.count] if n.object == leaf)
    assert n.decrements == 4
    f.m.put(leaf + 0x44, 5 << 20)
    assert f.build() == SAFE
    assert f.classify() == SAFE
    f.m.put(leaf + 0x44, 3 << 20)
    assert f.build() == SAFE
    assert f.classify() == UNKNOWN  # underflow is not an ordinary retirement


@pytest.mark.parametrize("flags", [0x400, 2 << 11])
def test_optional_and_other_language_skip(f, flags):
    bad = f.make_node(refs=1)
    f.edges(bad, [(bad, 0)])  # would be a cycle if followed
    f.edges(f.roots[0], [(f.models[0], 0), (bad, flags)])
    f.m.put(f.roots[0] + 0x44, 2 << 20)
    assert f.build() == SAFE
    assert bad not in [n.object for n in f.p.nodes[: f.p.count]]
    assert f.classify() == SAFE


def test_current_language_and_resident(f):
    bad = f.make_node()
    f.edges(bad, [(bad, 0)])
    f.edges(f.roots[0], [(bad, 1 << 11)])
    assert f.build() == SAFE
    assert bad in [n.object for n in f.p.nodes[: f.p.count]]
    f.m.put(bad + 0x44, 0x80000)  # resident with no reference counter
    assert f.build() == SAFE


def test_duplicate_segment_roots_are_deduplicated(f):
    f.set_segment(0, [f.roots[0], f.roots[0]])
    f.m.put(f.roots[0] + 0x44, 2 << 20)
    assert f.build() == SAFE
    assert f.classify() == SAFE
    n = next(n for n in f.r.nodes[: f.r.count] if n.object == f.roots[0])
    assert n.decrements == 1


def test_cycle_capacities_and_unverified_proof(f):
    assert f.build() == SAFE
    f.r = workspace(1)
    assert f.classify() == UNKNOWN
    f.p = workspace(511)
    assert f.build() == UNKNOWN
    f.p = workspace()
    f.defs[0].constructor_verified = 0
    assert f.build() == UNKNOWN
    f.defs[0].constructor_verified = 1
    f.edges(f.roots[0], [(f.roots[0], 0)])
    assert f.build() == SAFE  # native cycle dedup terminates
    f.r = workspace(4096)
    assert f.classify() == UNKNOWN  # ref1 < self + self-edge decrements


def test_bad_sheet_model_owner_and_record_bounds(f):
    good = f.m.get(f.desc(f.models[0]) + 20)
    f.m.put(f.desc(f.models[0]) + 20, f.models[1])
    assert f.build() == UNKNOWN
    f.m.put(f.desc(f.models[0]) + 20, good)
    f.defs[0].address += 4  # interior, not a record boundary
    assert f.build() == UNKNOWN
    f.defs[0].address -= 4
    assert f.build() == SAFE
    assert f.classify(h=f.c.headers[0].object) == UNKNOWN
    f.m.put(f.models[0] + 0x3C, 0x1FFFFFC)
    assert f.classify() == UNKNOWN


def test_quiescence_generation_and_stale_identity(f):
    assert f.build() == SAFE
    f.c.quiescent = 0
    assert f.classify() == UNKNOWN
    f.c.quiescent = 1
    f.c.source_guards_verified = 0
    assert f.classify() == UNKNOWN
    f.c.source_guards_verified = 1
    f.m.put(f.generation, 20)
    assert f.classify() == UNKNOWN
    f.m.put(f.generation, 19)
    f.m.put(f.roots[0], f.m.alloc())
    assert f.classify() == UNKNOWN


def test_changed_during_read_fails_closed(f):
    assert f.build() == SAFE
    target = f.roots[0]
    calls = 0

    def change(a):
        nonlocal calls
        if a == target:
            calls += 1
            if calls == 2:
                f.m.put(target, f.m.alloc())

    f.m.after_read = change
    assert f.classify() == UNKNOWN


def test_texture_5_6_counts_and_separate_transactions(f):
    root = f.roots[0]
    f.m.put(f.textures + 4, root)
    f.m.put(f.textures, 0)  # op5 ignores texture-table count
    assert f.build() == SAFE
    assert f.classify(op=5) == RETIRE
    assert f.classify(op=6) == SAFE
    f.m.put(f.textures, 123)  # op6 does NOT preserve a positive count as a hold
    assert f.classify(op=6) == RETIRE
    f.m.put(root + 0x44, 3 << 20)
    f.m.put(f.textures + 8, 2)
    f.m.put(f.textures + 12, root)
    assert f.build() == SAFE
    assert f.classify(op=6) == SAFE
    n = next(n for n in f.r.nodes[: f.r.count] if n.object == root)
    assert n.decrements == 2
    f.m.put(root + 0x44, 2 << 20)
    assert f.build() == SAFE
    assert f.classify(op=6) == RETIRE


def test_op3_other_ops_negative_texture_and_bad_inputs(f):
    assert f.build() == SAFE
    assert f.classify(op=3) == UNKNOWN
    for op in (0, 2, 4, 7, 8, 9, 10, 11, 12):
        assert f.classify(op=op) == SAFE
    assert f.classify(op=13) == UNKNOWN
    assert f.classify(op=5, seg=0xFFFFFFFF) == SAFE
    assert f.classify(seg=32) == UNKNOWN
    f.m.fail_address = f.roots[0] + 0x38
    assert f.classify() == UNKNOWN


def test_incomplete_workspace_stale_model_and_bad_stride(f):
    assert f.build() == SAFE
    f.p.count -= 1
    assert f.classify() == UNKNOWN
    assert f.build() == SAFE
    resource = f.p.models[0]
    f.m.put(resource, f.m.alloc())
    assert f.classify() == UNKNOWN
    assert f.build() == SAFE
    f.m.put(f.desc(f.models[0]) + 12, 0xFFFFFFFF)
    assert f.build() == UNKNOWN


def test_header_list_cycle_and_limits(f):
    f.m.put(f.models[0] + 0x54, f.models[0])
    assert f.build() == UNKNOWN
    f.m.put(f.models[0] + 0x54, 0)
    assert f.build() == SAFE
    f.r.capacity = 4097
    assert f.classify() == UNKNOWN
    f.r.capacity = 4096
    f.r.nodes = f.p.nodes
    assert f.classify() == UNKNOWN


def append_owner_members(f, count):
    """Unrelated records in an existing verified list, not extra graph nodes."""
    owner = f.roots[0]
    header = f.m.get(owner + 0x3C)
    typ = f.m.get(f.desc(owner) + 8)
    stride = f.m.get(typ + 12)
    members = []
    previous = owner
    for _ in range(count):
        obj, descriptor, base, raw = [
            f.m.alloc(size) for size in (0x60, 0x40, stride, 4)
        ]
        for offset, value in (
            (0, raw),
            (8, 5),
            (0x38, descriptor),
            (0x3C, header),
            (0x44, 10 << 20),
        ):
            f.m.put(obj + offset, value)
        for offset, value in ((8, typ), (12, 1), (16, base), (20, obj)):
            f.m.put(descriptor + offset, value)
        f.m.put(previous + 0x54, obj)
        members.append(obj)
        previous = obj
    return members


@pytest.mark.parametrize(
    "corruption",
    [
        "next",
        "cycle",
        "parent",
        "type",
        "raw",
        "backlink",
        "duplicate_header",
        "duplicate_list",
    ],
)
def test_definition_walk_checks_every_unrelated_member(f, corruption):
    members = append_owner_members(f, 4)
    last = members[-1]
    if corruption == "next":
        f.m.put(last + 0x54, 0x7FFFF)
    elif corruption == "cycle":
        f.m.put(last + 0x54, members[0])
    elif corruption == "parent":
        f.m.put(last + 0x3C, f.headers[0][0])
    elif corruption == "type":
        f.m.put(last + 8, 4)
    elif corruption == "raw":
        f.m.put(last, 0)
    elif corruption == "backlink":
        f.m.put(f.desc(last) + 20, members[0])
    elif corruption == "duplicate_header":
        # Even a duplicate header with no matching definition is malformed.
        f.headers.append(f.headers[0])
    elif corruption == "duplicate_list":
        f.m.put(f.headers[0][0] + 0x40, f.roots[0])
    assert f.build() == UNKNOWN
    assert not f.p.complete


@pytest.mark.parametrize("corruption", ["next", "cycle", "parent", "type", "raw"])
def test_arbitrary_node_revalidation_still_checks_membership(f, corruption):
    members = append_owner_members(f, 4)
    assert f.build() == SAFE
    last = members[-1]
    offset, value = {
        "next": (0x54, 0x7FFFF),
        "cycle": (0x54, members[0]),
        "parent": (0x3C, f.headers[0][0]),
        "type": (8, 4),
        # The raw field is checked by definition discovery, not by member().
        # Exercise a protected owner's raw identity at revalidation instead.
        "raw": (0, 0),
    }[corruption]
    f.m.put((f.roots[0] if corruption == "raw" else last) + offset, value)
    assert f.classify() == UNKNOWN


def test_definition_walk_unrelated_members_have_linear_read_cost(lib):
    counts = []
    for count in (0, 64, 128):
        f = Fixture(lib)
        append_owner_members(f, count)
        f.m.put(f.roots[0] + 0x44, 2 << 20)
        before = f.m.read32_count
        assert f.build() == SAFE
        counts.append(f.m.read32_count - before)
        assert f.p.count == 8
        assert f.classify() == SAFE
    # Graph and definitions are identical: doubling unrelated list members must
    # double incremental reads, not recreate one full membership scan per node.
    assert counts[2] - counts[0] <= 2 * (counts[1] - counts[0]) + 64
    assert counts[2] < 30000


def test_provisional_protected_dependency_must_be_in_authoritative_list(f):
    orphan = f.make_node()
    f.m.put(f.m.get(orphan + 0x3C) + 0x40, 0)
    f.edges(f.roots[0], [(f.models[0], 0), (orphan, 0)])
    # Structurally valid fields and a real header are not proof of membership.
    assert f.build() == UNKNOWN
    assert not f.p.complete


@pytest.mark.parametrize("retire_candidate", [False, True])
def test_provisional_release_dependency_cannot_publish_safe_or_retire(
    f, retire_candidate
):
    root, orphan = f.make_node(), f.make_node()
    targets = [(orphan, 0)]
    if retire_candidate:
        targets.append((f.models[0], 0))
        f.m.put(f.models[0] + 0x44, 2 << 20)
    f.edges(root, targets)
    f.set_segment(0, [root])
    f.m.put(f.m.get(orphan + 0x3C) + 0x40, 0)
    assert f.build() == SAFE
    assert f.classify() == UNKNOWN
    assert not f.r.complete


@pytest.mark.parametrize(
    "corruption", ["missing", "cross_list", "cycle", "duplicate_header"]
)
def test_batch_membership_rechecks_all_headers_after_build(f, corruption):
    assert f.build() == SAFE
    root = f.roots[0]
    header = f.m.get(root + 0x3C)
    if corruption == "missing":
        f.m.put(header + 0x40, 0)
    elif corruption == "cross_list":
        # This unrelated header is not claimed by any selected node.
        other = f.make_node()
        f.m.put(f.m.get(other + 0x3C) + 0x40, root)
        f.refresh_config()
    elif corruption == "cycle":
        # A cycle in an unrelated list must not hide behind selected headers.
        other = f.make_node()
        f.m.put(other + 0x54, other)
        f.refresh_config()
    else:
        f.headers.append(f.headers[0])
        f.refresh_config()
    assert f.classify() == UNKNOWN
    assert not f.r.complete


@pytest.mark.parametrize("corruption", ["head", "parent", "raw", "references"])
def test_late_change_between_provisional_collection_and_validation(f, corruption):
    extra = f.make_node()
    f.edges(f.roots[0], [(f.models[0], 0), (extra, 0)])
    trigger = f.m.get(f.desc(f.roots[0]) + 28)
    fired = False

    def change(address):
        nonlocal fired
        # Definition discovery fingerprints this word, before graph collection.
        # Wait for graph traversal's next read of that reference's symbol.
        nonlocal reads
        if address != trigger:
            return
        reads += 1
        if reads != 2:
            return
        fired = True
        if corruption == "head":
            f.m.put(f.m.get(extra + 0x3C) + 0x40, 0)
        elif corruption == "parent":
            f.m.put(extra + 0x3C, f.headers[0][0])
        elif corruption == "raw":
            f.m.put(f.roots[0], f.m.alloc())
        else:
            f.m.put(trigger, f.desc(extra))

    reads = 0
    f.m.after_read = change
    assert f.build() == UNKNOWN
    assert fired and not f.p.complete


def test_final_membership_validation_follows_last_dependency_reads(f):
    assert f.build() == SAFE
    reference = f.m.get(f.desc(f.roots[0]) + 28)
    reads = 0

    def change(address):
        nonlocal reads
        if address == reference:
            reads += 1
            # Initial field validation, initial dependency validation, then
            # final dependency validation. Final membership must follow this.
            if reads == 3:
                f.m.put(f.m.get(f.roots[0] + 0x3C) + 0x40, 0)

    f.m.after_read = change
    assert f.classify(op=12) == UNKNOWN
    assert reads >= 3 and not f.r.complete


def test_duplicate_selected_object_is_not_two_membership_proofs(f):
    assert f.build() == SAFE
    f.p.nodes[f.p.count] = f.p.nodes[0]
    f.p.count += 1
    assert f.classify() == UNKNOWN


def test_stage_counter_changed_during_read(f):
    assert f.build() == SAFE
    f.m.put8(f.counters, 2)
    calls = 0
    old = f.m.r8

    def changing(_, a, out):
        nonlocal calls
        result = old(None, a, out)
        if a == f.counters:
            calls += 1
            if calls == 1:
                f.m.put8(a, 1)
        return result

    callback = READ8(changing)
    f.c.read8 = callback
    assert f.classify() == UNKNOWN


@pytest.mark.parametrize("flags", [0x400, 2 << 11])
def test_segment_source_reference_flags(f, flags):
    f.m.put(f.desc(f.stage) + 0x30, flags)
    assert f.build() == SAFE
    assert f.classify() == SAFE


def test_classifier_never_mutates_protected_input_or_game_memory(f):
    assert f.build() == SAFE
    before = dict(f.m.overlay)
    image = C.string_at(f.p.nodes, f.p.count * C.sizeof(Node))
    f.m.put(f.request, 1)
    f.m.put(f.request + 8, f.c.stage_descriptor)
    f.m.put(f.request + 12, 0)
    before = dict(f.m.overlay)
    assert (
        f.lib.rs_classify(C.byref(f.c), f.request, C.byref(f.p), C.byref(f.p))
        == UNKNOWN
    )
    assert f.p.complete == 1
    assert C.string_at(f.p.nodes, f.p.count * C.sizeof(Node)) == image
    assert f.classify() == RETIRE
    assert f.m.overlay == before


@pytest.mark.parametrize("op", [5, 6])
@pytest.mark.parametrize("descriptor", [0, 0xFFFFFFFC, 0x80001, 0x1FFFFF0])
def test_texture_mandatory_descriptor_rejected(f, op, descriptor):
    assert f.build() == SAFE
    unrelated = f.make_node()
    f.refresh_config()
    f.m.put(unrelated + 0x38, descriptor)
    f.m.put(f.textures, 1)
    f.m.put(f.textures + 4, unrelated)
    assert f.classify(op=op) == UNKNOWN


def release_graph(f, count, shape="chain"):
    """Disjoint, valid release owners; no protected/model identity changes."""
    nodes = [f.make_node() for _ in range(count)]
    if shape == "chain":
        for a, b in itertools.pairwise(nodes):
            f.edges(a, [(b, 0)])
    else:
        f.edges(nodes[0], [(n, 0) for n in nodes[1:]])
    return nodes


@pytest.mark.parametrize("op", [1, 5])
@pytest.mark.parametrize("shape", ["chain", "star"])
@pytest.mark.parametrize("count, expected", [(1024, SAFE), (1025, UNKNOWN)])
def test_native_transaction_hash_limit(f, op, shape, count, expected):
    assert f.build() == SAFE
    nodes = release_graph(f, count, shape)
    f.refresh_config()
    if op == 1:
        f.set_segment(0, [nodes[0]])
    else:
        f.m.put(f.textures + 4, nodes[0])
    assert f.classify(op=op) == expected
    assert bool(f.r.complete) == (expected == SAFE)


@pytest.mark.parametrize("second, expected", [(512, SAFE), (513, UNKNOWN)])
@pytest.mark.parametrize("shape", ["chain", "star"])
def test_op1_all_roots_share_hash_limit(f, second, expected, shape):
    assert f.build() == SAFE
    left = release_graph(f, 512, shape)
    right = release_graph(f, second, shape)
    f.refresh_config()
    f.set_segment(0, [left[0], right[0]])
    assert f.classify() == expected


def test_op1_duplicate_roots_do_not_consume_extra_hash_slots(f):
    assert f.build() == SAFE
    nodes = release_graph(f, 1024)
    f.refresh_config()
    f.set_segment(0, [nodes[0], nodes[0]])
    assert f.classify() == SAFE
    assert f.r.count == 1024


def test_op6_aggregate_can_exceed_native_per_texture_limit(f):
    assert f.build() == SAFE
    left = release_graph(f, 600)
    right = release_graph(f, 600)
    f.refresh_config()
    for index, root in enumerate((left[0], right[0])):
        f.m.put(f.textures + 8 * index, 1)
        f.m.put(f.textures + 8 * index + 4, root)
    assert f.classify(op=6) == SAFE
    assert f.r.count == 1200


def test_op6_rejects_one_oversized_texture_transaction(f):
    assert f.build() == SAFE
    small = release_graph(f, 2)
    oversized = release_graph(f, 1025)
    f.refresh_config()
    for index, root in enumerate((small[0], oversized[0])):
        f.m.put(f.textures + 8 * index, 1)
        f.m.put(f.textures + 8 * index + 4, root)
    assert f.classify(op=6) == UNKNOWN
    assert not f.r.complete


@pytest.mark.parametrize("nested", [False, True])
def test_resident_protected_owner_does_not_hide_releasable_dependencies(f, nested):
    dep = f.make_node(refs=1)
    resident = f.make_node(refs=0) if nested else f.roots[0]
    f.m.put(resident + 0x44, 0x80000)
    # Include a native-deduplicated cycle through the protected main owner.
    f.edges(resident, [(dep, 0), (f.roots[0], 0), (f.models[0], 0)])
    if nested:
        f.edges(f.roots[0], [(resident, 0), (f.models[0], 0)])
    f.set_segment(0, [dep])
    assert f.build() == SAFE
    assert dep in [n.object for n in f.p.nodes[: f.p.count]]
    assert resident in [n.object for n in f.p.nodes[: f.p.count]]
    assert f.classify() == RETIRE
    # Releasing the resident itself still follows native exclusion semantics.
    f.set_segment(0, [resident])
    assert f.classify() == SAFE
    assert not f.r.count


@pytest.mark.parametrize("flags", [0x400, 2 << 11])
def test_protected_resident_dependencies_keep_optional_language_filter(f, flags):
    dep = f.make_node(refs=1)
    f.m.put(f.roots[0] + 0x44, 0x80000)
    f.edges(f.roots[0], [(dep, flags), (f.models[0], 0)])
    f.set_segment(0, [dep])
    assert f.build() == SAFE
    assert dep not in [n.object for n in f.p.nodes[: f.p.count]]
    assert f.classify() == SAFE


def make_extra(f, family=2):
    model = f.make_node(stride=16, refs=20)
    resource, nmo = f.m.alloc(), f.m.alloc()
    f.m.put(resource, f.m.alloc())
    f.m.put(resource + 8, 1)
    f.m.put(resource + 0x20, nmo)
    f.m.put(nmo, 0x004F4D4E)
    f.m.put(nmo + 4, 3)
    f.m.put(f.base(model) + 8, resource)
    slot = f.m.alloc(12)
    owner = f.make_node(stride=0x40, refs=1)
    definition = f.base(owner)
    offset = {0: 0x14, 1: 4, 2: 8}[family]
    field = definition + offset
    f.m.put(slot, f.desc(model))
    f.m.put(field, field - slot)
    f.edges(owner, [(model, 0)])
    return Definition(definition, family, 19, 1), owner, model, slot


def extend(f, proofs):
    array = (Definition * len(proofs))(*proofs) if proofs else None
    return f.lib.rs_extend_protected(C.byref(f.c), array, len(proofs), C.byref(f.p))


@pytest.mark.parametrize("family", [0, 1, 2])
@pytest.mark.parametrize("release_model", [False, True])
def test_extra_definition_and_model_are_protected(f, family, release_model):
    assert f.build() == SAFE
    proof, owner, model, _ = make_extra(f, family)
    if release_model:
        f.m.put(model + 0x44, 1 << 20)
    f.refresh_config()
    f.set_segment(0, [model if release_model else owner])
    assert f.classify() == SAFE  # formerly outside all four root graphs
    assert extend(f, [proof]) == SAFE
    assert f.p.extra_count == 1
    binding = f.p.extras[0]
    assert binding.proof.address == proof.address
    assert binding.definition_owner == owner and binding.model_owner == model
    assert {owner, model}.issubset({n.object for n in f.p.nodes[: f.p.count]})
    assert f.classify() == RETIRE


@pytest.mark.parametrize("change", ["resolution", "raw", "header", "owner", "proof"])
def test_extra_bindings_revalidated_before_safe(f, change):
    assert f.build() == SAFE
    proof, owner, model, slot = make_extra(f)
    f.refresh_config()
    assert extend(f, [proof]) == SAFE
    resource = f.p.extras[0].model
    if change == "resolution":
        f.m.put(slot, f.desc(f.models[1]))
    elif change == "raw":
        f.m.put(resource, f.m.alloc())
    elif change == "header":
        f.m.put(resource + 0x20, f.p.model_headers[0])
    elif change == "owner":
        f.m.put(f.desc(model) + 0x14, owner)
    else:
        f.p.extras[0].proof.constructor_verified = 0
    assert f.classify(op=0) == UNKNOWN


@pytest.mark.parametrize(
    "bad", ["unverified", "generation", "family", "interior", "model"]
)
def test_extra_malformed_proof_invalidates_closure(f, bad):
    assert f.build() == SAFE
    proof, _, _, slot = make_extra(f)
    f.refresh_config()
    if bad == "unverified":
        proof.constructor_verified = 0
    elif bad == "generation":
        proof.generation = 18
    elif bad == "family":
        proof.family = 99
    elif bad == "interior":
        proof.address += 4
    else:
        f.m.put(slot, 0)
    assert extend(f, [proof]) == UNKNOWN
    assert not f.p.complete
    assert f.classify(op=0) == UNKNOWN


def test_extra_resident_root_retains_dependencies(f):
    assert f.build() == SAFE
    proof, owner, model, _ = make_extra(f)
    dep = f.make_node(refs=1)
    f.m.put(owner + 0x44, 0x80000)
    f.edges(owner, [(dep, 0), (model, 0)])
    f.refresh_config()
    assert extend(f, [proof]) == SAFE
    f.set_segment(0, [dep])
    assert f.classify() == RETIRE


def test_extra_count_limit_cumulative_and_rebuild_clear(f):
    assert f.build() == SAFE
    proofs = [make_extra(f)[0] for _ in range(33)]
    f.refresh_config()
    assert extend(f, proofs[:16]) == SAFE
    assert extend(f, proofs[16:32]) == SAFE
    assert f.p.extra_count == 32
    assert extend(f, proofs[32:]) == UNKNOWN
    assert not f.p.complete
    assert f.build() == SAFE
    assert f.p.extra_count == 0
    assert all(not b.proof.address and not b.model for b in f.p.extras)


def test_extra_duplicate_and_empty_extension(f):
    assert f.build() == SAFE
    assert extend(f, []) == SAFE
    proof, _, _, _ = make_extra(f)
    f.refresh_config()
    assert extend(f, [proof]) == SAFE
    assert extend(f, [proof]) == UNKNOWN
    assert not f.p.complete
    assert f.build() == SAFE
    assert extend(f, [f.defs[0]]) == UNKNOWN


def test_extra_capacity_overflow_is_fail_closed(f):
    assert f.build() == SAFE
    proof, owner, model, _ = make_extra(f)
    chain = release_graph(f, 503)
    f.edges(owner, [(model, 0), (chain[0], 0)])
    f.refresh_config()
    assert extend(f, [proof]) == UNKNOWN
    assert not f.p.complete and f.p.count <= 512
    assert f.classify(op=0) == UNKNOWN


def test_extra_requires_complete_current_snapshot(f):
    assert extend(f, []) == UNKNOWN
    assert f.build() == SAFE
    f.c.quiescent = 0
    assert extend(f, []) == UNKNOWN
    assert not f.p.complete


def test_extra_invalid_count_null_input_and_partial_failure(f):
    assert f.build() == SAFE
    assert f.lib.rs_extend_protected(C.byref(f.c), None, 33, C.byref(f.p)) == UNKNOWN
    assert not f.p.complete
    assert f.build() == SAFE
    assert f.lib.rs_extend_protected(C.byref(f.c), None, 1, C.byref(f.p)) == UNKNOWN
    assert f.build() == SAFE
    first = make_extra(f)[0]
    second = make_extra(f)[0]
    second.constructor_verified = 0
    f.refresh_config()
    assert extend(f, [first, second]) == UNKNOWN
    assert f.p.extra_count == 1 and not f.p.complete
    assert f.classify(op=0) == UNKNOWN


def test_extra_model_index_bounds_rechecked(f):
    assert f.build() == SAFE
    proof, _, _, _ = make_extra(f)
    f.refresh_config()
    assert extend(f, [proof]) == SAFE
    field = proof.address + 8
    f.m.put(field, f.m.get(field) | (1 << 18))  # one-past a one-record model sheet
    assert f.classify(op=0) == UNKNOWN


def test_extra_workspace_preserves_original_prefix():
    class OriginalWorkspace(C.Structure):
        _fields_ = Workspace._fields_[:-2]

    for name, _ in OriginalWorkspace._fields_:
        assert (
            getattr(Workspace, name).offset == getattr(OriginalWorkspace, name).offset
        )
    assert Workspace.extra_count.offset == C.sizeof(OriginalWorkspace)
    assert C.sizeof(Workspace) > C.sizeof(OriginalWorkspace)
