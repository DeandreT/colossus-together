"""Offline emitted-instruction tests; synthetic memory only, no game/assets I/O."""

import os
import re
import shutil
import struct
from dataclasses import replace
from itertools import pairwise
from types import SimpleNamespace

import pytest
import test_native_lifecycle_hooks as model

from native_lifecycle import retry_hook as h


def config():
    return h.Config(
        g=0x300000,
        original_scr_run=0x1600000,
        expected_call=h._jal(0x1600000),
        state=0x478038,
        code=0x1400000,
        context=0x1508030,
        context_size=0x400,
        should_retry=0x1600100,
        retry_selected=0x1600200,
        trusted_code=((0x1600000, 0x1000),),
    )


def provider(context):
    """Contract mock, deliberately not an implementation of the C provider."""
    return (
        context.enabled
        and context.coop
        and context.phase == "QUIESCENT"
        and not context.held
        and not context.owned_refs
        and context.menu_ready
        and context.death_epoch > 0
        and context.death_epoch == context.current_epoch
        and context.death_epoch != context.consumed_epoch
    )


def ready_context(**changes):
    values = {
        "enabled": True,
        "coop": True,
        "phase": "QUIESCENT",
        "held": 0,
        "owned_refs": 0,
        "menu_ready": True,
        "death_epoch": 7,
        "current_epoch": 7,
        "consumed_epoch": 6,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class Machine(model.Machine):
    """Execute actual rendered instructions, including suspended call/resume.

    The original and callbacks overwrite their outgoing homes and clobber every
    GPR lane except SP/RA, all FPRs, FCSR, both HI/LO lanes and SA. FPACC/VU
    sentinels are never touched. The pure provider mock owns the epoch policy.
    """

    def __init__(self, c=None, *, state=0, context=None, changed_state=None):
        super().__init__(SimpleNamespace(canonical_group=0x830000))
        self.c = c or config()
        self.context = context or ready_context()
        self.changed_state = changed_state
        self.mem[self.c.state] = state
        self.entry = self.snapshot()
        self.writes = []
        self.fpacc, self.vu = 0x7FA12345, (0x12345678,) * 32
        self.lines, self.labels = [], {}
        for line in h.render(self.c, h.guard_expectations(self.c)).splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.lines)
            elif not line.startswith("."):
                self.lines.append(line)
        self.pc = self.labels["hook_retry"]
        self.suspended = False

    def home_clobber(self):
        for offset in range(0, 64, 16):
            self.mem[self.low("sp") + offset] = (1 << 127) | offset

    def original_returns(self):
        self.home_clobber()
        self.clobber(101)
        self.post = self.snapshot()
        self.suspended = False

    def external(self, name, pause):
        self.events.append(name)
        if name == "original_scr_run":
            assert self.events == [name], "original must run exactly once"
            for i in range(1, 32):
                if i not in (29, 31):
                    assert self.r[i] == self.entry[0][i], (
                        f"changed original arg/register {i}"
                    )
            assert self.low("sp") == (self.entry[0][29] & model.MASK64) - h.PRE_FRAME
            self.home_clobber()
            if pause:
                self.suspended = True
            else:
                self.original_returns()
            return
        assert self.low("a0") == self.c.context
        assert (
            self.low("sp")
            == (self.entry[0][29] & model.MASK64) - h.PRE_FRAME - h.POST_FRAME
        )
        self.home_clobber()
        if name == "should_retry":
            answer = provider(self.context)
            if self.changed_state is not None:
                self.mem[self.c.state] = self.changed_state
            self.clobber(202)
            self.set("v0", int(answer))
        else:
            assert name == "retry_selected"
            assert self.mem[self.c.state] == 1, "publish Retry before consuming epoch"
            self.context.consumed_epoch = self.context.death_epoch
            self.clobber(303)

    def run(self, *, pause=False):
        assert not self.suspended, "resume original before resuming caller"
        for _ in range(500):
            op, *tail = self.lines[self.pc].split(maxsplit=1)
            self.pc += 1
            args = tail[0].split(", ") if tail else []
            if op == "nop":
                continue
            if op in ("beq", "bne", "jal", "jr"):
                assert self.lines[self.pc] == "nop"
                self.pc += 1
                if op == "jr":
                    assert self.r[31] == self.entry[0][31]
                    return
                if op == "jal":
                    self.set("ra", self.c.code + self.pc * 4)
                    self.external(args[0], pause)
                    if self.suspended:
                        return
                elif (self.low(args[0]) == self.low(args[1])) == (op == "beq"):
                    self.pc = self.labels[args[2]]
            elif op in ("sq", "lq", "sw", "lw", "swc1", "lwc1"):
                match = re.fullmatch(r"(-?\d+)\((\$\w+)\)", args[1])
                address = self.low(match[2]) + int(match[1])
                if op in ("sq", "sw", "swc1"):
                    value = (
                        self.f[int(args[0][2:])]
                        if op == "swc1"
                        else self.r[self.idx(args[0])]
                    )
                    self.mem[address] = value if op == "sq" else value & 0xFFFFFFFF
                    self.writes.append((op, address))
                else:
                    self.reads.append(address)
                    value = self.mem[address]
                    if op == "lwc1":
                        self.f[int(args[0][2:])] = value
                    elif op == "lq":
                        self.r[self.idx(args[0])] = value
                    else:
                        self.set(
                            args[0], ((value & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000
                        )
            elif op in ("lui", "addiu"):
                imm = args[-1]
                if imm.startswith("%"):
                    address = getattr(self.c, imm[imm.index("(") + 1 : -1])
                    value = (
                        (address + 0x8000) >> 16
                        if imm.startswith("%hi")
                        else ((address & 0xFFFF) ^ 0x8000) - 0x8000
                    )
                else:
                    value = int(imm)
                value = value << 16 if op == "lui" else self.low(args[1]) + value
                self.set(args[0], ((value & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000)
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
                raise AssertionError(op)
        raise AssertionError("wrapper did not return")

    def assert_preserved(self):
        expected = self.post[0].copy()
        expected[29], expected[31] = self.entry[0][29], self.entry[0][31]
        assert self.snapshot() == (expected, *self.post[1:])
        assert self.fpacc == 0x7FA12345 and self.vu == (0x12345678,) * 32
        sp = self.entry[0][29] & model.MASK64
        assert all(
            sp - h.PRE_FRAME - h.POST_FRAME <= address < sp or address == self.c.state
            for _, address in self.writes
        )


@pytest.mark.parametrize("state", [1, 2, 3, 4, 5, 6, 7, 8, 0xFFFFFFFF])
def test_nonwaiting_state_never_calls_policy(state):
    m = Machine(state=state)
    m.run()
    m.assert_preserved()
    assert m.mem[m.c.state] == state
    assert m.events == ["original_scr_run"]


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": False},
        {"coop": False},
        {"phase": "ACTIVE"},
        {"phase": "RETIRING"},
        {"held": 1},
        {"owned_refs": 1},
        {"menu_ready": False},
        {"death_epoch": 0},
        {"current_epoch": 8},
        {"consumed_epoch": 7},
    ],
)
def test_provider_contract_false_does_not_write_or_consume(changes):
    m = Machine(context=ready_context(**changes))
    m.run()
    m.assert_preserved()
    assert m.mem[m.c.state] == 0
    assert m.events == ["original_scr_run", "should_retry"]
    assert all(address != m.c.state for _, address in m.writes)


def test_true_selects_once_then_provider_rejects_same_epoch():
    context = ready_context()
    for expected in (1, 0):
        m = Machine(context=context)
        m.run()
        m.assert_preserved()
        assert m.mem[m.c.state] == expected
        assert sum(address == m.c.state for _, address in m.writes) == expected
        assert m.events == ["original_scr_run", "should_retry"] + (
            ["retry_selected"] if expected else []
        )
    assert context.consumed_epoch == context.death_epoch


@pytest.mark.parametrize("state", [1, 2, 5, 8])
def test_callback_changing_state_cannot_be_clobbered_or_consumed(state):
    m = Machine(changed_state=state)
    m.run()
    m.assert_preserved()
    assert m.mem[m.c.state] == state
    assert m.events == ["original_scr_run", "should_retry"]
    assert m.context.consumed_epoch == 6


def test_original_yield_keeps_small_frame_and_resumes_without_second_call():
    m = Machine()
    m.run(pause=True)
    assert m.suspended and m.post is None
    assert m.events == ["original_scr_run"] and m.mem[m.c.state] == 0
    sp = m.entry[0][29] & model.MASK64
    assert all(sp - h.PRE_FRAME <= a < sp for _, a in m.writes)
    # The coroutine may use the whole home area before eventually returning.
    m.original_returns()
    m.run()
    m.assert_preserved()
    assert m.events == ["original_scr_run", "should_retry", "retry_selected"]


def test_fixed_revision_guards_delay_and_update_order():
    c = config()
    words = h.guard_expectations(c)
    assert c.call_site == c.g + 0x552B0
    assert words[c.call_site + 4] == 0
    assert words[c.g + 0x5529C] == 0x0060F809
    assert words[c.g + 0x552A8] == 0x0040F809
    assert words[c.g + 0x552B8] == 0x16A0FF87
    for address in words:
        changed = dict(words)
        changed[address] ^= 1
        with pytest.raises(ValueError):
            h.render(c, changed)
        del changed[address]
        with pytest.raises(ValueError):
            h.render(c, changed)
    text = h.render(c, words)
    before, after = text.split("jal original_scr_run\n")
    assert h.PRE_FRAME <= 128
    assert before.count("addiu $sp") == 1
    assert f"addiu $sp, $sp, -{h.POST_FRAME}" in after
    assert text.count("jal original_scr_run") == 1 and text.count("jal ") == 3
    assert ".bss" not in text
    assert (
        len(
            [
                x
                for x in text.splitlines()
                if not x.startswith(".") and not x.endswith(":")
            ]
        )
        * 4
        <= h.CODE_SIZE
    )
    assert words == h.guard_expectations(c)


@pytest.mark.parametrize(
    "changes",
    [
        {"g": True},
        {"g": 0x1FFFFF0},
        {"g": 0x300004},
        {"state": 0},
        {"state": 0xA0478038},
        {"state": 0x478039},
        {"state": 0x1400000},
        {"state": 0x1508030},
        {"state": 0x1600000},
        {"state": 0x355000},
        {"code": 0x355000},
        {"context": 0x355000},
        {"code": 0x1FFFFF0},
        {"context_size": 0},
        {"context_size": True},
        {"context_size": 0x1000000},
        {"context": 0x1400000},
        {"expected_call": 0},
        {"expected_call": True},
        {"expected_call": h._jal(0x1600300)},
        {"should_retry": 0x1700000},
        {"retry_selected": 0x1600000},
        {"should_retry": 0x1600200},
        {"original_scr_run": 0xA1600000},
        {"trusted_code": ()},
        {"trusted_code": ((0x1600000, True),)},
        {"trusted_code": ((0x1600000, 0x1000), (0x1600100, 0x100))},
    ],
)
def test_reject_unsafe_or_inconsistent_bindings(changes):
    with pytest.raises(ValueError):
        replace(config(), **changes)


ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@pytest.mark.skipif(not ASSEMBLER, reason="optional EE binutils not configured")
@pytest.mark.parametrize("shift", [0, 0x18000])
def test_real_ee_assembly_relocations_and_unapplied_patch(shift):
    c = replace(config(), code=config().code + shift, state=config().state + shift)
    words = h.guard_expectations(c)
    before = dict(words)
    result = h.build(c, words, assembler=ASSEMBLER)
    assert words == before
    assert result.patches == (
        h.WordPatch(
            c.call_site, c.expected_call, h._jal(result.linked.exports["hook_retry"])
        ),
    )
    instructions = {}
    for payload in result.linked.payloads:
        assert (
            c.code
            <= payload.address
            <= payload.address + len(payload.data)
            <= c.code + h.CODE_SIZE
        )
        assert payload.section == ".text" or not payload.data
        for offset in range(0, len(payload.data), 4):
            instructions[payload.address + offset] = struct.unpack_from(
                "<I", payload.data, offset
            )[0]
    calls = []
    for pc, word in instructions.items():
        if word >> 26 == 3:
            calls.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
            assert instructions[pc + 4] == 0
    assert calls == [c.original_scr_run, c.should_retry, c.retry_selected]
    # Signed LO16 reconstruction: emitted loads must resolve exact addresses.
    loads = []
    ordered = sorted(instructions.items())
    for (pc, high), (next_pc, low) in pairwise(ordered):
        if high >> 26 == 15 and low >> 26 == 9 and next_pc == pc + 4:
            reg = (high >> 16) & 31
            if (low >> 21) & 31 == reg and (low >> 16) & 31 == reg:
                loads.append(
                    ((high & 0xFFFF) << 16) + ((low & 0xFFFF) ^ 0x8000) - 0x8000
                )
    assert loads == [c.state, c.context, c.state, c.context]
