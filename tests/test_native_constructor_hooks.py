"""Offline instruction-model tests and real R5900 assembly/link coverage."""

import os
import shutil
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_native_lifecycle_hooks as model

from native_lifecycle import constructor_hooks as h


def config():
    return h.Config(
        m=0x300000,
        code=0x1400000,
        context=0x1500000,
        context_size=0x1000,
        previous_char_entry=0x1600000,
        previous_alias_entry=0x1600800,
        expected_char_entry=(h._j(0x1600000), 0),
        expected_alias_entry=(h._j(0x1600800), 0),
        observe=0x1601000,
        trusted_code=((0x1600000, 0x2000),),
    )


class Machine(model.Machine):
    """Use the existing emitted-instruction interpreter, not a hook simulation."""

    def __init__(self, c, family, success):
        super().__init__(SimpleNamespace(canonical_group=0x830000), success=success)
        self.c, self.family = c, family
        # Distinct values, including full upper lanes, exercise all eight args.
        for index in range(4, 12):
            self.r[index] = ((0xFEDCBA + index) << 96) | (0x830000 + index * 16)
        self.entry = self.snapshot()

    def external(self, name):
        self.events.append((name, tuple(self.low(r) for r in ("a0", "a1", "a2", "a3"))))
        if name in ("previous_char_entry", "previous_alias_entry"):
            assert name == (
                "previous_char_entry"
                if self.family == h.CHARACTER
                else "previous_alias_entry"
            )
            assert self.post is None, "previous constructor must run exactly once"
            for i in range(1, 32):
                if i not in (29, 31):
                    assert self.r[i] == self.entry[0][i], f"changed input register {i}"
            assert h.PRE_FRAME <= 128
            assert self.low("sp") == (self.entry[0][29] & model.MASK64) - h.PRE_FRAME
            assert self.low("sp") % 16 == 0
            # Callee may use all 64 outgoing home bytes without touching saved metadata.
            for offset in range(0, 64, 16):
                self.mem[self.low("sp") + offset] = 0xBAD
            self.clobber(101)
            self.set("v0", self.success)
            self.post = self.snapshot()
        elif name == "observe":
            assert tuple(self.low(r) for r in ("a0", "a1", "a2", "a3")) == (
                self.c.context,
                self.success,
                self.entry[0][5] & model.MASK64,
                self.family,
            )
            assert self.low("sp") == (
                (self.entry[0][29] & model.MASK64) - h.PRE_FRAME - h.FRAME
            )
            # Even callee-saved GPRs, both HI/LO lanes, SA and FCSR are clobbered.
            self.clobber(303)
        else:
            raise AssertionError(f"unexpected call seam: {name}")

    def assert_preserved(self):
        expected = self.post[0].copy()
        expected[29], expected[31] = self.entry[0][29], self.entry[0][31]
        assert self.snapshot() == (expected, *self.post[1:])
        sp = self.entry[0][29] & model.MASK64
        assert all(sp - h.PRE_FRAME - h.FRAME <= address < sp for address in self.reads)


@pytest.mark.parametrize(
    "family,name", [(h.CHARACTER, "character"), (h.ALIAS, "alias")]
)
@pytest.mark.parametrize("result", [0, 0x850000])
def test_eight_arguments_minimal_preframe_and_full_poststate(
    monkeypatch, family, name, result
):
    monkeypatch.setattr(model, "h", h)
    m = Machine(config(), family, result)
    m.run("hook_" + name)
    assert [event[0] for event in m.events] == [
        "previous_char_entry" if family == h.CHARACTER else "previous_alias_entry",
        *(["observe"] if result else []),
    ]
    # Includes original v0/v1/f0, upper GPR lanes, special registers and SP/RA.
    m.assert_preserved()
    original_sp = m.entry[0][29] & model.MASK64
    assert m.mem[original_sp - h.PRE_FRAME + h.PARAMETERS] == m.entry[0][6]
    assert m.mem[original_sp - h.PRE_FRAME + h.DEFINITION] == m.entry[0][5]


def test_every_entry_and_nearby_guard_is_exact_and_required():
    c = config()
    for address in h.guard_expectations(c):
        words = h.guard_expectations(c)
        words[address] ^= 1
        with pytest.raises(ValueError):
            h.render(c, words)
        del words[address]
        with pytest.raises(ValueError):
            h.render(c, words)


@pytest.mark.parametrize(
    "changes",
    [
        {"m": 0},
        {"m": 0x1FFFFF0},
        {"code": 0x1FFF000},
        {"code": True},
        {"context": 0x1400000},
        {"context_size": 0},
        {"context_size": True},
        {"context_size": 0x1000000},
        {"trusted_code": ()},
        {"trusted_code": ((0x1600000, 0),)},
        {"trusted_code": ((0x1FFFFF0, 0x1000),)},
        {"trusted_code": ((0x1600000, 0x2000), (0x1601000, 0x1000))},
        {"trusted_code": ((0x1400000, 0x400000),)},
        {"previous_char_entry": 0x1700000},
        {"previous_alias_entry": 0x1700000},
        {"observe": 0x1700000},
        {"observe": 0x1602000},
        {"previous_char_entry": 0x1600002},
        {"expected_char_entry": (0x27BDFCF0, 0x0000702D)},
        {"expected_alias_entry": (0x27BDFE90, 0x3C020003)},
        {"expected_char_entry": (0x0C000000 | (0x1600000 >> 2), 0)},
        {"expected_alias_entry": (h._j(0x1600000), 0)},
        {"expected_char_entry": (h._j(0x1600000), 1)},
        {"expected_char_entry": (h._j(0x1600000), False)},
        {"context": 0x3832D0},
    ],
)
def test_reject_unknown_entry_and_invalid_bounds(changes):
    with pytest.raises(ValueError):
        replace(config(), **changes)


ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@pytest.mark.skipif(not ASSEMBLER, reason="optional EE binutils not configured")
@pytest.mark.parametrize("shift", [0, 0x18000])
def test_actual_assembler_two_relocation_bases_no_mistargeted_seams(shift):
    c = config()
    c = replace(c, m=c.m + shift, code=c.code + shift, context=c.context + shift)
    words = h.guard_expectations(c)
    before = dict(words)
    result = h.build(c, words, assembler=ASSEMBLER)
    assert words == before
    assert len(result.patches) == 2
    for patch, offset, name in zip(
        result.patches, (h.CHAR_ENTRY, h.ALIAS_ENTRY), ("character", "alias")
    ):
        assert patch.address == c.m + offset
        assert patch.expected == words[patch.address]
        assert patch.replacement == h._j(result.linked.exports["hook_" + name])
        assert words[patch.address + 4] == 0  # guarded NOP is not a no-op patch
    assert {p.address for p in result.patches}.isdisjoint(
        {c.previous_char_entry, c.previous_alias_entry, c.observe}
    )
    assert all(
        c.code <= p.address and p.address + len(p.data) <= c.code + h.CODE_SIZE
        for p in result.linked.payloads
    )
    # Inspect real instructions after relocation, not just assembly text.
    instructions = {}
    for payload in result.linked.payloads:
        for pos in range(0, len(payload.data) - 3, 4):
            instructions[payload.address + pos] = struct.unpack_from(
                "<I", payload.data, pos
            )[0]
    exports = result.linked.exports
    for name, target in (
        ("character", c.previous_char_entry),
        ("alias", c.previous_alias_entry),
    ):
        start = exports["hook_" + name]
        end = exports["hook_alias"] if name == "character" else max(instructions) + 4
        calls = []
        for pc in range(start, end, 4):
            word = instructions[pc]
            if word >> 26 == 3:
                calls.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
                assert instructions[pc + 4] == 0
        assert calls == [target, c.observe]
        # The original constructor is never re-entered through its patched entry.
        assert c.m + h.CHAR_ENTRY not in calls and c.m + h.ALIAS_ENTRY not in calls
    assert sum(len(p.data) for p in result.linked.payloads) < h.CODE_SIZE
