"""Offline instruction interpreter plus optional actual EE assembler coverage."""

import os
import re
import shutil
from dataclasses import replace

import pytest

from native_lifecycle import hooks as h


def config():
    return h.Config(
        g=0x100000,
        k=0x500000,
        code=0x1400000,
        context=0x1500000,
        context_size=0x1000,
        original_group_add=0x519BF0,
        previous_free_target=0x1600000,
        expected_group_call=h._jal(0x519BF0),
        expected_free_call=h._jal(0x1600000),
        canonical_group=0x3002B0,
        get_first=0x51A000,
        canonical_admitted=0x1600100,
        allocation_freed=0x1600200,
        trusted_code=((0x1600000, 0x1000),),
    )


NAMES = dict(
    zip(
        [
            "zero",
            "at",
            "v0",
            "v1",
            "a0",
            "a1",
            "a2",
            "a3",
            "t0",
            "t1",
            "t2",
            "t3",
            "t4",
            "t5",
            "t6",
            "t7",
            "s0",
            "s1",
            "s2",
            "s3",
            "s4",
            "s5",
            "s6",
            "s7",
            "t8",
            "t9",
            "k0",
            "k1",
            "gp",
            "sp",
            "fp",
            "ra",
        ],
        range(32),
    )
)
MASK64 = (1 << 64) - 1


class Machine:
    """Execute emitted instructions, not a second high-level hook implementation.

    External callees deliberately clobber every register except SP/RA, including
    the upper 64 GPR bits, FPRs, both HI/LO lanes, SA and FCSR. No game code runs.
    """

    def __init__(self, c, *, actor=0x800000, group=None, success=1, first=None):
        self.c = c
        self.r = [(0xABCD0000 + i) << 64 | (0x1000 + i) for i in range(32)]
        self.r[0] = 0
        self.r[29] = (0xABCDE << 64) | 0x1F00000
        self.r[31] = (0x12345 << 64) | 0x110000
        self.set("a0", actor)
        self.set("a1", c.canonical_group if group is None else group)
        self.f = [0x7FC00000 + i for i in range(32)]
        self.hi, self.lo, self.sa, self.fcsr = 2**120 + 3, 2**100 + 4, 7, 9
        self.mem = {}
        self.events = []
        self.success, self.first = success, actor if first is None else first
        self.entry = self.snapshot()
        self.post = None
        self.reads = []

    def idx(self, reg):
        name = reg.lstrip("$")
        return int(name) if name.isdigit() else NAMES[name]

    def low(self, reg):
        return self.r[self.idx(reg)] & MASK64

    def set(self, reg, value):
        i = self.idx(reg)
        if i:
            self.r[i] = (self.r[i] & ~MASK64) | (value & MASK64)

    def snapshot(self):
        return (self.r.copy(), self.f.copy(), self.hi, self.lo, self.sa, self.fcsr)

    def clobber(self, seed):
        for i in range(1, 32):
            if i not in (29, 31):
                self.r[i] = ((seed + i) << 96) | (seed * 37 + i)
        self.f = [seed + i for i in range(32)]
        self.hi, self.lo, self.sa, self.fcsr = (
            2**115 + seed,
            2**126 + seed,
            seed,
            seed + 1,
        )

    def external(self, name):
        args = tuple(self.low(r) for r in ("a0", "a1"))
        self.events.append((name, args))
        if name in ("original_group_add", "previous_free_target"):
            for i in range(1, 32):
                if i not in (29, 31):
                    assert self.r[i] == self.entry[0][i], f"altered input register {i}"
            assert self.low("sp") == (self.entry[0][29] & MASK64) - h.FRAME
            assert self.low("sp") % 16 == 0
            self.clobber(101)
            self.set("v0", self.success)
            self.post = self.snapshot()
        elif name == "get_first":
            assert args[0] == self.c.canonical_group
            self.clobber(202)
            self.set("v0", self.first)
        else:
            assert args == (self.c.context, self.entry[0][4] & MASK64)
            self.clobber(303)

    def run(self, name):
        text = h.render(self.c, h.guard_expectations(self.c))
        lines, labels = [], {}
        for line in text.splitlines():
            if line.endswith(":"):
                labels[line[:-1]] = len(lines)
            elif not line.startswith("."):
                lines.append(line)
        pc = labels[name]
        for _ in range(1000):
            line = lines[pc]
            pc += 1
            op, *tail = line.split(maxsplit=1)
            args = tail[0].split(", ") if tail else []
            if op == "nop":
                continue
            if op in ("beq", "bne", "jal", "jr"):
                assert lines[pc] == "nop", "interpreter requires explicit no-op delay"
                pc += 1
                if op == "jr":
                    return
                if op == "jal":
                    self.set("ra", 0x1400000 + pc * 4)
                    self.external(args[0])
                elif (self.low(args[0]) == self.low(args[1])) == (op == "beq"):
                    pc = labels[args[2]]
                continue
            if op in ("sq", "lq", "sw", "lw", "swc1", "lwc1"):
                match = re.fullmatch(r"(-?\d+)\((\$\w+)\)", args[1])
                address = self.low(match[2]) + int(match[1])
                if op.startswith("s"):
                    self.mem[address] = (
                        self.f[int(args[0][2:])]
                        if op == "swc1"
                        else self.r[self.idx(args[0])]
                    )
                else:
                    self.reads.append(address)
                    value = self.mem[address]
                    if op == "lwc1":
                        self.f[int(args[0][2:])] = value
                    elif op == "lq":
                        self.r[self.idx(args[0])] = value
                    else:
                        value &= 0xFFFFFFFF
                        self.set(args[0], value if value < 2**31 else value - 2**32)
            elif op in ("lui", "addiu"):
                imm = args[-1]
                if imm.startswith("%"):
                    symbol = imm[imm.index("(") + 1 : -1]
                    value = (
                        self.c.context
                        if symbol == "callback_context"
                        else getattr(self.c, symbol)
                    )
                    value = (
                        (value + 0x8000) >> 16
                        if imm.startswith("%hi")
                        else ((value & 65535) ^ 32768) - 32768
                    )
                else:
                    value = int(imm)
                self.set(
                    args[0], value << 16 if op == "lui" else self.low(args[1]) + value
                )
            elif op in ("pmfhi", "pmflo"):
                self.r[self.idx(args[0])] = self.hi if op == "pmfhi" else self.lo
            elif op in ("pmthi", "pmtlo"):
                setattr(
                    self, "hi" if op == "pmthi" else "lo", self.r[self.idx(args[0])]
                )
            elif op in ("mfsa", "cfc1"):
                self.set(args[0], self.sa if op == "mfsa" else self.fcsr)
            elif op in ("mtsa", "ctc1"):
                setattr(
                    self,
                    "sa" if op == "mtsa" else "fcsr",
                    self.low(args[0]) & 0xFFFFFFFF,
                )
            else:
                raise AssertionError(line)
        raise AssertionError("did not return")

    def assert_preserved(self):
        expected = self.post[0].copy()
        expected[29], expected[31] = self.entry[0][29], self.entry[0][31]
        assert self.snapshot() == (expected, *self.post[1:])
        # All memory reads are in the private frame: never inspect the actor,
        # freed allocation, group contents, or a host-controlled function table.
        sp = self.entry[0][29] & MASK64
        assert all(sp - h.FRAME <= address < sp for address in self.reads)


@pytest.mark.parametrize(
    "success,group,actor,first,events",
    [
        (
            1,
            None,
            0x800000,
            None,
            ["original_group_add", "get_first", "canonical_admitted"],
        ),
        (0, None, 0x800000, None, ["original_group_add"]),
        (1, 0x3002B4, 0x800000, None, ["original_group_add"]),
        (1, None, 0x800000, 0x800010, ["original_group_add", "get_first"]),
        (1, None, 0x800000, 0, ["original_group_add", "get_first"]),
        (1, None, 0, 0, ["original_group_add"]),
    ],
)
def test_admission_instructions(success, group, actor, first, events):
    m = Machine(config(), success=success, group=group, actor=actor, first=first)
    m.run("hook_canonical_admission")
    assert [name for name, _ in m.events] == events
    m.assert_preserved()


@pytest.mark.parametrize("stock", [True, False])
@pytest.mark.parametrize("allocation", [0, 0x800000])
def test_final_free_instructions(stock, allocation):
    c = config()
    if stock:
        c = replace(
            c,
            previous_free_target=c.k + 0x39C8,
            expected_free_call=h._jal(c.k + 0x39C8),
        )
    m = Machine(c, actor=allocation, success=0xDEADBEEF)
    m.run("hook_final_free")
    assert [name for name, _ in m.events] == [
        "previous_free_target",
        "allocation_freed",
    ]
    m.assert_preserved()


def test_every_guard_is_required_and_exact():
    c = config()
    words = h.guard_expectations(c)
    for address in words:
        bad = dict(words)
        bad[address] ^= 1
        with pytest.raises(ValueError):
            h.render(c, bad)
        del bad[address]
        with pytest.raises(ValueError):
            h.render(c, bad)


@pytest.mark.parametrize(
    "changes",
    [
        {"canonical_group": 0},
        {"context": 0},
        {"context_size": 0},
        {"canonical_admitted": 0x1700000},
        {"allocation_freed": 0x1700000},
        {"context": 0x1400000},
        {"expected_free_call": h._jal(0x5039C8)},
        {"expected_group_call": 0},
        {"trusted_code": ()},
        {"previous_free_target": 0x1700000, "expected_free_call": h._jal(0x1700000)},
    ],
)
def test_reject_invalid_bindings(changes):
    with pytest.raises(ValueError):
        replace(config(), **changes)


ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@pytest.mark.skipif(not ASSEMBLER, reason="optional EE binutils not configured")
def test_real_ee_assembly_link_and_unapplied_plan():
    c = config()
    words = h.guard_expectations(c)
    before = dict(words)
    result = h.build(c, words, assembler=ASSEMBLER)
    assert words == before
    assert len(result.patches) == 2
    for patch, name in zip(result.patches, ("canonical_admission", "final_free")):
        assert patch.expected == words[patch.address]
        assert patch.replacement == h._jal(result.linked.exports["hook_" + name])
        assert patch.address + 4 not in {p.address for p in result.patches}
    assert sum(len(p.data) for p in result.linked.payloads) < h.CODE_SIZE
    assert result.assembly.count("jal original_group_add") == 1
    assert result.assembly.count("jal previous_free_target") == 1
