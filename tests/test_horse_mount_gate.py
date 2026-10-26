"""Synthetic-only execution of emitted instructions; no game data discovery."""

import os
import re
import shutil
from dataclasses import replace

import pytest

from horse_mount import gate as h


def config():
    return h.Config(
        entry=0x200000,
        native_size=0x200,
        prologue=(0x27BDFF80, 0xFFB40060),
        caller_return=0x210000,
        callbacks=(0x220000, 0x220100, 0x220200),
        code=0x300000,
        code_size=0x2000,
        arm=0x310000,
        players=(0x400000, 0x410000),
        horse=0x420000,
        pending_owner=0x500000,
        pending_committed=0x500004,
        registration=tuple(
            h.Guard(0x510000 + i * 4, a)
            for i, a in enumerate((0x400000, 0x410000, 0x420000))
        ),
        generation=(h.Guard(0x520000, 7), h.Guard(0x520004, 7)),
        source_guards=(h.Guard(0x230000, 0),),
        lifetime_guards=(h.Guard(0x530000, 1),),
        contract=h.SourceContract(
            "Synthetic entry ABI review", ("v0", "v1"), True, True, True
        ),
    )


def values(c):
    return {g.address: g.expected for g in h.guard_expectations(c)}


class Machine:
    """Bounded emitted-assembly interpreter with real branch delay execution.

    Registers retain full 128-bit sentinels; FP and special state is independent.
    Loads require initialized memory, detecting accidental unknown dereferences.
    """

    names = {
        "zero": 0,
        "v0": 2,
        "v1": 3,
        "a0": 4,
        "a1": 5,
        "s4": 20,
        "sp": 29,
        "ra": 31,
    }
    mask = (1 << 64) - 1

    def __init__(self, *, actor=0, route=0, alignment=0):
        self.c = config()
        self.r = [(0xAABBCCDD00110000 + i) << 64 | (0xDEAD0000 + i) for i in range(32)]
        self.r[0] = 0
        self.f = tuple(0xA1230000 + i for i in range(32))
        self.special = (0xFEDCBA9876543210, 0x123456789ABCDEF0, 0x1234, 0x9876)
        self.mem, self.writes = {}, []
        for g in h.guard_expectations(self.c):
            self.put(g.address, g.expected, g.width)
        self.put(self.c.arm, 1)
        self.set("sp", 0x600000 + alignment)
        self.set("a0", self.low("sp"))
        self.set("a1", self.c.players[actor])
        self.set("ra", self.c.caller_return)
        self.put(self.low("sp") + 8, 1)
        self.put(self.low("sp") + 32, self.c.callbacks[route])
        obj, valid = h.ROUTES[route]
        self.put(self.low("a1") + obj, self.c.horse)
        self.put(self.low("a1") + obj + 48, 1)
        self.put(self.low("a1") + valid, 1)
        self.put(self.c.horse + h.RELATION_OFFSET, self.c.players[1 - actor])
        self.put(self.c.pending_owner, self.c.players[1 - actor])
        self.put(self.c.pending_committed, 1)
        for i, p in enumerate(self.c.players):
            control = 0x700000 + i * 0x10000
            self.put(p + h.CONTROL_OFFSET, control)
            self.put(control + h.MOUNTED_OFFSET, 1)
        self.lines, self.labels = [], {}
        for line in h.render(self.c, values(self.c)).splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.lines)
            elif not line.startswith(".") or line.startswith(".word"):
                self.lines.append(line)

    def index(self, name):
        return self.names[name.removeprefix("$")]

    def low(self, name):
        return self.r[self.index(name)] & self.mask

    def set(self, name, value):
        i = self.index(name)
        self.r[i] = (self.r[i] & ~self.mask) | (value & self.mask)

    def put(self, address, value, width=4):
        for i in range(width):
            self.mem[address + i] = (value >> (8 * i)) & 255

    def get(self, address, width=4):
        assert address % width == 0
        return sum(self.mem[address + i] << (8 * i) for i in range(width))

    def run(self):
        before, memory = list(self.r), dict(self.mem)
        fp, special = self.f, self.special
        pc, pending = 0, None
        prologues = 0
        for _ in range(2000):
            line = self.lines[pc]
            op, *tail = line.split(maxsplit=1)
            args = tail[0].split(", ") if tail else []
            target, pending = pending, None
            if op == "nop":
                pass
            elif op == "lui":
                value = int(args[1]) << 16
                self.set(args[0], value - (1 << 32) if value & 0x80000000 else value)
            elif op == "ori":
                self.set(args[0], self.low(args[1]) | int(args[2]))
            elif op == "addiu":
                self.set(args[0], self.low(args[1]) + int(args[2]))
            elif op in ("sltiu", "sltu"):
                right = int(args[2]) if op == "sltiu" else self.low(args[2])
                self.set(args[0], int(self.low(args[1]) < right))
            elif op in ("lw", "lbu"):
                m = re.fullmatch(r"(\d+)\((\$\w+)\)", args[1])
                value = self.get(self.low(m[2]) + int(m[1]), 1 if op == "lbu" else 4)
                if op == "lw" and value & 0x80000000:
                    value |= 0xFFFFFFFF00000000
                self.set(args[0], value)
            elif op in ("beq", "bne"):
                if (self.low(args[0]) == self.low(args[1])) == (op == "beq"):
                    pending = self.labels[args[2]]
            elif op == "j":
                pending = self.labels.get(args[0], "original")
            elif op == "jr":
                assert self.low(args[0]) == self.c.caller_return
                pending = "denied"
            elif op == "daddu":
                self.set(args[0], self.low(args[1]) + self.low(args[2]))
            elif op == ".word":
                word = int(args[0])
                if word == self.c.prologue[0]:
                    prologues += 1
                    self.set("sp", self.low("sp") + (word & 65535) - 65536)
                else:
                    assert word == self.c.prologue[1]
                    address = self.low("sp") + (word & 65535)
                    value = self.r[(word >> 16) & 31] & self.mask
                    self.put(address, value, 8)
                    self.writes.append((address, value))
            else:
                raise AssertionError(line)
            if isinstance(target, str):
                deny = target == "denied"
                assert prologues == (0 if deny else 1)
                for i in set(range(32)) - {2, 3, 29}:
                    assert self.r[i] == before[i], i
                assert self.f == fp and self.special == special
                if deny:
                    assert self.r[29] == before[29]
                    assert (
                        self.low("v0") == 0 and not self.writes and self.mem == memory
                    )
                else:
                    assert self.r[29] == before[29] - 128
                    assert self.writes == [
                        ((before[29] & self.mask) - 32, before[20] & self.mask)
                    ]
                return deny
            pc = target if target is not None else pc + 1
        raise AssertionError("unbounded emitted gate")


@pytest.mark.parametrize("actor", (0, 1))
@pytest.mark.parametrize("route", range(3))
@pytest.mark.parametrize("alignment", (0, 8))
def test_occupied_both_directions_routes_and_stack_alignment(actor, route, alignment):
    assert Machine(actor=actor, route=route, alignment=alignment).run()


@pytest.mark.parametrize("actor", (0, 1))
@pytest.mark.parametrize("committed", (0, 123, "horse"))
def test_other_pending_denied_without_new_reservation(actor, committed):
    m = Machine(actor=actor)
    m.put(m.c.horse + h.RELATION_OFFSET, m.c.horse)
    m.put(m.c.pending_committed, m.c.horse if committed == "horse" else committed)
    assert m.run()


@pytest.mark.parametrize(
    "scenario",
    (
        "idle",
        "self",
        "unknown_relation",
        "unknown_pending",
        "stale_committed",
        "disarmed",
        "wrong_caller",
        "wrong_actor",
        "wrong_record",
        "null_request",
        "unknown_callback",
        "invalid_route",
        "other_object",
        "nonmount",
    ),
)
def test_fallthrough_original_prologue_once(scenario):
    m = Machine()
    if scenario in ("idle", "unknown_pending", "stale_committed"):
        m.put(m.c.horse + h.RELATION_OFFSET, m.c.horse)
    if scenario == "idle":
        m.put(m.c.pending_owner, 0)
    if scenario == "self":
        m.put(m.c.horse + h.RELATION_OFFSET, m.c.players[0])
        m.put(m.c.pending_owner, m.c.players[0])
    if scenario == "unknown_relation":
        m.put(m.c.horse + h.RELATION_OFFSET, 0x777770)
    if scenario == "unknown_pending":
        m.put(m.c.pending_owner, 0x777770)
    if scenario == "stale_committed":
        m.put(m.c.pending_committed, 1)
        m.put(0x710000 + h.MOUNTED_OFFSET, 0)
    if scenario == "disarmed":
        m.put(m.c.arm, 0)
    if scenario == "wrong_caller":
        # The real return remains unknown but fallthrough never uses it.
        m.set("ra", 0x240000)
    if scenario == "wrong_actor":
        m.set("a1", 0x777770)
    if scenario == "wrong_record":
        m.set("a0", 0x777770)
    if scenario == "null_request":
        m.put(m.low("sp") + 8, 0)
    if scenario == "unknown_callback":
        m.put(m.low("sp") + 32, 0x240000)
    obj, valid = h.ROUTES[0]
    if scenario == "invalid_route":
        m.put(m.c.players[0] + valid, 0)
    if scenario == "other_object":
        m.put(m.c.players[0] + obj, 0x777770)
    if scenario == "nonmount":
        m.put(m.c.players[0] + obj + 48, 6)
    assert not m.run()


def test_each_guard_runtime_mismatch_bypasses_and_build_preflight_rejects():
    c = config()
    for g in h.guard_expectations(c):
        m = Machine()
        m.put(g.address, g.expected ^ 1, g.width)
        # The original entry guards apply only before installation, not after
        # those two words have been replaced by the jump/NOP.
        assert m.run() == (g.address in (c.entry, c.entry + 4))
        changed = values(c)
        changed[g.address] ^= 1
        with pytest.raises(ValueError):
            h.render(c, changed)
        del changed[g.address]
        with pytest.raises(ValueError):
            h.render(c, changed)


@pytest.mark.parametrize("flags", (0x20000, 0x40000, 0xFFFFFF00))
@pytest.mark.parametrize("actor", range(3))
def test_header_flags_are_not_character_type(flags, actor):
    m = Machine()
    m.put((*m.c.players, m.c.horse)[actor] + h.TYPE_OFFSET, flags | 9)
    assert m.run()


@pytest.mark.parametrize("actor", range(3))
@pytest.mark.parametrize("wrong", (0, 8, 10, 255))
def test_wrong_type_byte_bypasses(actor, wrong):
    m = Machine()
    m.put((*m.c.players, m.c.horse)[actor] + h.TYPE_OFFSET, 0x40000 | wrong)
    assert not m.run()


def test_emission_never_uses_interrupted_kernel_registers_or_calls():
    text = h.render(config(), values(config()))
    assert not re.search(r"\$(?:k[01]|at|gp|t\d|s\d|f\d)\b", text)
    assert "jal" not in text and "sw " not in text and "sq " not in text
    assert {g.width for g in h.guard_expectations(config())} == {1, 4}


def test_installed_entry_does_not_disable_runtime_checks():
    m = Machine()
    m.put(m.c.entry, 0x08000000 | (m.c.code >> 2))
    m.put(m.c.entry + 4, 0)
    assert m.run()


@pytest.mark.parametrize("alignment", (0, 8))
def test_fallthrough_preserves_full_registers_with_either_alignment(alignment):
    m = Machine(alignment=alignment)
    m.put(m.c.arm, 0)
    assert not m.run()


@pytest.mark.parametrize("actor", (0, 1))
def test_other_pending_overrides_self_relation(actor):
    m = Machine(actor=actor)
    m.put(m.c.horse + h.RELATION_OFFSET, m.c.players[actor])
    assert m.run()


@pytest.mark.parametrize("control", (0, 0x710000))
def test_committed_pending_retained_for_null_or_mounted_control(control):
    m = Machine()
    m.put(m.c.horse + h.RELATION_OFFSET, m.c.horse)
    m.put(m.c.pending_committed, 1)
    m.put(m.c.players[1] + h.CONTROL_OFFSET, control)
    assert m.run()


@pytest.mark.parametrize("actor", (0, 1))
@pytest.mark.parametrize("committed", (1, 2, 0xFFFFFFFF))
def test_nonzero_committed_flag_allows_native_stale_reservation_reclaim(actor, committed):
    m = Machine(actor=actor)
    other = m.c.players[1 - actor]
    m.put(m.c.horse + h.RELATION_OFFSET, m.c.horse)
    m.put(m.c.pending_committed, committed)
    control = m.get(other + h.CONTROL_OFFSET)
    m.put(control + h.MOUNTED_OFFSET, 0)
    assert not m.run()


@pytest.mark.parametrize("actor", (0, 1))
def test_uncommitted_reservation_is_not_reclaimed_even_when_unmounted(actor):
    m = Machine(actor=actor)
    other = m.c.players[1 - actor]
    m.put(m.c.horse + h.RELATION_OFFSET, m.c.horse)
    m.put(m.c.pending_committed, 0)
    m.put(m.get(other + h.CONTROL_OFFSET) + h.MOUNTED_OFFSET, 0)
    assert m.run()


def test_all_actor_high_header_flags_together():
    m = Machine()
    for a in (*m.c.players, m.c.horse):
        m.put(a + h.TYPE_OFFSET, 0xFFFFFF09)
    assert m.run()


@pytest.mark.parametrize(
    "changes",
    (
        {"code": True},
        {"code": 0x300004},
        {"code_size": 0},
        {"code_size": 0x2000000},
        {"code": 0x1FFFFF0},
        {"arm": 0x300010},
        {"entry": 0x400004},
        {"entry": 0x2FFFF8},
        {"entry": h.RAM_END - 8},
        {"native_size": 0},
        {"native_size": 8},
        {"native_size": 14},
        {"native_size": True},
        {"arm": 0x200008},
        {"arm": 0x400100},
        {"pending_owner": 0x500004},
        {"players": (0x400000, 0x400000)},
        {"horse": 0x410100},
        {"callbacks": (0x220000, 0x220000, 0x220200)},
        {"callbacks": (0x300000, 0x220100, 0x220200)},
        {"callbacks": (True, 0x220100, 0x220200)},
        {"caller_return": 0x200004},
        {"prologue": (0, 0)},
        {"prologue": (0x27BDFF81, 0xFFB40060)},
        {"prologue": (0x27BDFF80, 0xFFA20060)},
        {"prologue": (0x27BDFF80, 0xFFB40080)},
        {"generation": ()},
        {"generation": (h.Guard(0x520000, 0),)},
        {"registration": ()},
        {"source_guards": ()},
        {"lifetime_guards": ()},
        {"players": [0x400000, 0x410000]},
        {"contract": None},
        {"lifetime_guards": (h.Guard(0x300000, 1),)},
        {"lifetime_guards": (h.Guard(0x520000, 1),)},
    ),
)
def test_invalid_bindings(changes):
    with pytest.raises(ValueError):
        replace(config(), **changes)


def test_original_continuation_cannot_be_replaced_by_payload():
    # The old eight-byte-only check let the gate overwrite entry+8, which
    # fallthrough executes after replaying the prologue.
    with pytest.raises(ValueError):
        replace(config(), entry=config().code - 8)
    with pytest.raises(ValueError):
        replace(config(), code=config().entry + 16)


@pytest.mark.parametrize(
    "args",
    (
        (True, 1),
        (0x1001, 1),
        (0x1000, True),
        (0x1000, 256, 1),
        (0x1000, 1, True),
        (0x1000, 1, 2),
        (0x1FFFFFF, 1, 4),
    ),
)
def test_guard_schema(args):
    with pytest.raises(ValueError):
        h.Guard(*args)


def test_explicit_source_contract_and_capacity():
    with pytest.raises(ValueError):
        replace(config().contract, dead_registers=("v0",))
    with pytest.raises(ValueError):
        replace(config().contract, callback_routes_reviewed=False)
    c = replace(config(), code_size=16)
    with pytest.raises(ValueError):
        h.render(c, values(c))


ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@pytest.mark.skipif(not ASSEMBLER, reason="optional EE binutils not configured")
def test_actual_ee_assembly_and_unapplied_placement():
    c = config()
    before = values(c)
    result = h.build(c, before, assembler=ASSEMBLER)
    assert before == values(c)
    assert result.patches == (
        h.WordPatch(c.entry, c.prologue[0], 0x08000000 | (c.code >> 2)),
        h.WordPatch(c.entry + 4, c.prologue[1], 0),
    )
    assert result.linked.exports["occupied_gate"] == c.code
    arm = [p for p in result.linked.payloads if p.section == ".mount_arm"]
    assert len(arm) == 1 and arm[0].address == c.arm and arm[0].data == bytes(4)
