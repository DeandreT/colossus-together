"""Offline instruction-level render completion tests; no emulator or game I/O."""

import hashlib
import os
import re
import shutil
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_native_lifecycle_hooks as model

from native_lifecycle import render_hook as h


def config():
    return h.Config(
        call_site=0x320000,
        expected_call=h._jal(0x1600000),
        expected_delay=0x24840010,  # addiu a0,a0,16: must remain at the call site
        actual_render=0x1601000,
        code=0x1400000,
        counter=0x1508030,  # also exercises signed LO16 relocation
        trusted_code=((0x1600000, 0x2000),),
    )


def fenced_config():
    return replace(config(), fence_target=0x1601800, fence_state=0x1518040)


def stacked_config(fenced=False, size=0x10000):
    return replace(
        fenced_config() if fenced else config(),
        target_stack=(0x1800000, size),
        stack_state=0x1700000,
    )


class Yielded(Exception):
    pass


class Machine(model.Machine):
    """Reuse the existing register/state model, executing the emitted subset.

    Unlike the general hook model, addiu here models the EE's 32-bit signed
    result and sw stores just a word. This matters at both carry boundaries.
    """

    def __init__(
        self,
        c,
        count=0,
        result=0,
        fault=0,
        yields=False,
        fence_result=0,
        fence_yields=False,
    ):
        super().__init__(SimpleNamespace(canonical_group=0x830000))
        self.c, self.result, self.yields = c, result, yields
        self.fence_result = fence_result
        self.fence_yields = fence_yields
        for i in range(4, 12):
            self.r[i] = ((0xFEDCBA + i) << 96) | (0x830000 + i * 16)
        # Model entry after the original call site's unchanged delay word.
        self.set("a0", self.low("a0") + 16)
        self.entry = self.snapshot()
        self.mem.update(
            {
                c.counter: count & 0xFFFFFFFF,
                c.counter + 4: count >> 32,
                c.counter + 8: fault,
                c.counter + 12: 0xABCDEF12,
            }
        )
        self.writes = []
        self.initial_counter = {
            a: self.mem[a] for a in range(c.counter, c.counter + 16, 4)
        }
        if c.stack_state is not None:
            self.mem.update(
                {
                    c.stack_state: 0,
                    c.stack_state + 4: 0,
                    c.stack_state + 8: 0x1234,
                    c.stack_state + 12: 0xABCD,
                }
            )
        self.deep_writes = []

    @property
    def render_sp(self):
        return (
            sum(self.c.target_stack)
            if self.c.target_stack is not None
            else self.entry[0][29] & model.MASK64
        ) - h.PRE_FRAME

    def external(self, name):
        if name == "fence_target":
            assert self.events == ["actual_render"]
            assert self.low("a0") == self.c.fence_state
            assert self.low("sp") == self.render_sp - h.POST_FRAME
            assert self.low("sp") % 16 == 0
            assert {
                a: self.mem[a] for a in self.initial_counter
            } == self.initial_counter
            self.events.append(name)
            # The fence can use its entire outgoing home area and clobber all
            # GPR lanes (including GP), FPU/FCSR, HI/LO and SA, except SP/RA.
            for offset in range(0, 64, 16):
                self.mem[self.low("sp") + offset] = (1 << 126) | offset
            if self.fence_yields:
                raise Yielded
            self.clobber(303)
            self.set("v0", self.fence_result)
            return
        assert name == "actual_render"
        assert not self.events, "exactly one actual render call"
        self.events.append(name)
        for i in range(1, 32):
            if i not in (29, 31):
                assert self.r[i] == self.entry[0][i], f"changed input {i}"
        assert self.low("sp") == self.render_sp
        assert self.low("sp") % 16 == 0
        if self.c.target_stack is not None:
            assert self.mem[self.c.stack_state] == 1
            # Model 8 KiB of renderer stack use, beyond st_disp's 4 KiB.
            for offset in range(16, 8193, 16):
                address = self.low("sp") - offset
                base, size = self.c.target_stack
                assert base <= address < base + size
                self.mem[address] = 0xDEED0000 + offset
                self.deep_writes.append(address)
        for offset in range(0, 64, 16):
            self.mem[self.low("sp") + offset] = (1 << 127) | offset
        if self.yields:
            raise Yielded
        self.clobber(101)
        self.set("v0", self.result)
        self.post = self.snapshot()

    def run(self, resume=False):
        lines, labels = [], {}
        for line in h.render(self.c, h.guard_expectations(self.c)).splitlines():
            if line.endswith(":"):
                labels[line[:-1]] = len(lines)
            elif not line.startswith("."):
                lines.append(line)
        pc = self.continuation if resume else labels["hook_render"]
        for _ in range(500):
            op, *tail = lines[pc].split(maxsplit=1)
            pc += 1
            args = tail[0].split(", ") if tail else []
            if op == "nop":
                continue
            if op in ("beq", "bne", "jal", "jr"):
                assert lines[pc] == "nop"
                pc += 1
                if op == "jr":
                    assert self.r[31] == self.entry[0][31]
                    return
                if op == "jal":
                    self.set("ra", self.c.code + pc * 4)
                    self.continuation = pc
                    self.external(args[0])
                elif (self.low(args[0]) == self.low(args[1])) == (op == "beq"):
                    pc = labels[args[2]]
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
                    if address == self.c.stack_state and self.mem[address] == 0:
                        # Release only after abandoning the private stack.
                        assert self.r[29] == self.entry[0][29]
                else:
                    self.reads.append(address)
                    value = self.mem[address]
                    if op == "lwc1":
                        self.f[int(args[0][2:])] = value
                    elif op == "lq":
                        self.r[self.idx(args[0])] = value
                    else:
                        value &= 0xFFFFFFFF
                        self.set(args[0], (value ^ 0x80000000) - 0x80000000)
            elif op in ("lui", "addiu"):
                imm = args[-1]
                if imm.startswith("%"):
                    symbol = imm[imm.index("(") + 1 : -1]
                    address = (
                        sum(self.c.target_stack) - h.PRE_FRAME
                        if symbol == "target_stack_frame"
                        else getattr(self.c, symbol)
                    )
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
        assert self.events == ["actual_render"] + (
            ["fence_target"] if self.c.fence_target is not None else []
        )
        sp = self.entry[0][29] & model.MASK64

        def private(address):
            if self.c.target_stack is None:
                return False
            base, size = self.c.target_stack
            return base <= address < base + size

        assert all(
            sp
            - 96
            - (
                h.POST_FRAME
                if self.c.fence_target is not None and self.c.target_stack is None
                else 0
            )
            <= address
            < sp
            or address in (self.c.counter, self.c.counter + 4)
            or address == self.c.stack_state
            or private(address)
            for address in self.reads
        )
        assert self.mem[self.c.counter + 12] == 0xABCDEF12


@pytest.mark.parametrize("result", [0, 0x850000])
@pytest.mark.parametrize(
    "count",
    [
        0,
        1,
        0x7FFFFFFF,
        0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ],
)
def test_arguments_postcallee_state_and_completion(count, result):
    m = Machine(config(), count, result)
    m.run()
    m.assert_preserved()
    actual = m.mem[m.c.counter] | (m.mem[m.c.counter + 4] << 32)
    assert actual == min(count + 1, (1 << 64) - 1)
    assert m.mem[m.c.counter + 8] == int(count == (1 << 64) - 1)


def test_fault_is_sticky_and_saturation_never_resets():
    m = Machine(config(), (1 << 64) - 1)
    for _ in range(3):
        m.run()
        assert m.mem[m.c.counter] == m.mem[m.c.counter + 4] == 0xFFFFFFFF
        assert m.mem[m.c.counter + 8] == 1
        m.events.clear()
        m.entry = m.snapshot()
    m = Machine(config(), 41, fault=1)
    m.run()
    assert m.mem[m.c.counter] == 42
    assert m.mem[m.c.counter + 8] == 1


def test_coroutine_yield_does_not_publish_completion():
    m = Machine(config(), 19, yields=True)
    with pytest.raises(Yielded):
        m.run()
    assert m.mem[m.c.counter] == 19
    assert m.mem[m.c.counter + 4] == m.mem[m.c.counter + 8] == 0
    assert not any(
        m.c.counter <= address < m.c.counter + h.COUNTER_SIZE for _, address in m.writes
    )


@pytest.mark.parametrize("result", [0, 0x850000])
@pytest.mark.parametrize("fence_result", [0, 1, 0xFFFFFFFF])
@pytest.mark.parametrize("count", [0, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, (1 << 64) - 1])
def test_fence_result_controls_completion_and_preserves_full_render_state(
    result, fence_result, count
):
    m = Machine(fenced_config(), count, result, fence_result=fence_result)
    m.run()
    m.assert_preserved()
    actual = m.mem[m.c.counter] | (m.mem[m.c.counter + 4] << 32)
    assert actual == (count if fence_result else min(count + 1, (1 << 64) - 1))
    assert m.mem[m.c.counter + 8] == int(bool(fence_result) or count == (1 << 64) - 1)
    # A failed drain must not publish either counter word, even if the CPU
    # render reported success. The only counter-block store is the fault latch.
    if fence_result:
        assert [
            (op, address)
            for op, address in m.writes
            if m.c.counter <= address < m.c.counter + 16
        ] == [("sw", m.c.counter + 8)]


def test_fence_does_not_clear_existing_fault():
    m = Machine(fenced_config(), 19, fault=1)
    m.run()
    m.assert_preserved()
    assert m.mem[m.c.counter] == 20
    assert m.mem[m.c.counter + 8] == 1


def test_fenced_yield_neither_drains_nor_advances():
    m = Machine(fenced_config(), 19, yields=True)
    with pytest.raises(Yielded):
        m.run()
    assert m.events == ["actual_render"]
    assert {a: m.mem[a] for a in m.initial_counter} == m.initial_counter


def test_fence_uses_only_postcall_extra_stack_and_never_calls_after_publication():
    c = fenced_config()
    text = h.render(c, h.guard_expectations(c))
    before, after = text.split("jal actual_render\n", 1)
    assert before.count("addiu $sp") == 1
    assert f"addiu $sp, $sp, -{h.PRE_FRAME}" in before
    assert h.PRE_FRAME <= 128
    assert f"addiu $sp, $sp, -{h.POST_FRAME}" in after
    assert text.count("jal ") == 2
    assert "jal " not in text.split("jal fence_target\n", 1)[1]
    instructions = [
        line
        for line in text.splitlines()
        if not line.startswith(".") and not line.endswith(":")
    ]
    assert len(instructions) * 4 <= c.code_size
    assert c.code_size == h.FENCED_CODE_SIZE
    assert config().code_size == h.CODE_SIZE
    assert h.render(config(), h.guard_expectations(config())) == h.render(
        replace(config(), fence_target=None, fence_state=None),
        h.guard_expectations(config()),
    )


def test_default_assembly_remains_byte_for_byte_unchanged():
    c = config()
    assert hashlib.sha256(
        h.render(c, h.guard_expectations(c)).encode()
    ).hexdigest() == (
        "ba137f2d6e38c0c12d6586ab1685660be178727b929db821b17cc20d7dd36c6f"
    )


@pytest.mark.parametrize("fenced,fence_result", [(False, 0), (True, 0), (True, 7)])
@pytest.mark.parametrize("result", [0, 0x850000])
@pytest.mark.parametrize("count", [19, 0xFFFFFFFF, (1 << 64) - 1])
def test_private_stack_deep_render_preserves_original_stack_and_poststate(
    fenced, fence_result, result, count
):
    c = stacked_config(fenced)
    m = Machine(c, count, result, fence_result=fence_result)
    original_sp = 0x1069A30
    m.r[29] = (0xFEDCBA9876543210 << 64) | original_sp
    m.entry = m.snapshot()
    # Include the old stack and the object below it that motivated the guard.
    original = {
        address: 0xDA7A0000 + address
        for address in range(original_sp - 0x1100, original_sp, 16)
    }
    original[0x106897C] = 0xD15F1A7
    m.mem.update(original)
    m.run()
    m.assert_preserved()
    assert len(m.deep_writes) == 512
    assert min(m.deep_writes) == m.render_sp - 8192
    allowed = {original_sp - 96, original_sp - 80, original_sp - 32, original_sp - 16}
    assert all(m.mem[a] == value for a, value in original.items() if a not in allowed)
    assert m.mem[c.stack_state] == 0
    assert m.mem[c.stack_state + h.STACK_FAULT] == 0
    assert m.mem[c.stack_state + h.STACK_HIGHWATER] == 0x1234
    assert m.mem[c.stack_state + 12] == 0xABCD
    assert (m.mem[c.counter] | m.mem[c.counter + 4] << 32) == (
        count if fence_result else min(count + 1, (1 << 64) - 1)
    )
    assert m.mem[c.counter + h.COUNTER_FAULT] == int(
        bool(fence_result) or count == (1 << 64) - 1
    )
    assert m.mem[sum(c.target_stack) - 32] == m.entry[0][29]
    assert m.mem[sum(c.target_stack) - 16] == m.entry[0][31]


@pytest.mark.parametrize("fenced", [False, True])
def test_private_stack_keeps_sticky_faults_and_accepts_minimum_size(fenced):
    c = stacked_config(fenced, size=0x4000)
    m = Machine(c, 19, fault=1)
    m.mem[c.stack_state + h.STACK_FAULT] = 1
    m.run()
    m.assert_preserved()
    assert m.mem[c.counter] == 20
    assert m.mem[c.counter + h.COUNTER_FAULT] == 1
    assert m.mem[c.stack_state] == 0
    assert m.mem[c.stack_state + h.STACK_FAULT] == 1


@pytest.mark.parametrize("yielding", ["render", "fence"])
def test_private_stack_survives_native_yield_until_normal_return(yielding):
    c = stacked_config(True)
    m = Machine(
        c, 19, 0x850000, yields=yielding == "render", fence_yields=yielding == "fence"
    )
    with pytest.raises(Yielded):
        m.run()
    assert c.target_stack[0] <= m.low("sp") < sum(c.target_stack)
    assert m.mem[c.stack_state] == 1
    assert m.mem[c.counter] == 19
    # Resume at the saved JAL continuation, representing the native scheduler
    # restoring this coroutine and the callee finally returning normally.
    m.clobber(101 if yielding == "render" else 303)
    m.set("v0", m.result if yielding == "render" else 0)
    if yielding == "render":
        m.post = m.snapshot()
    m.run(resume=True)
    m.assert_preserved()
    assert m.mem[c.counter] == 20
    assert m.mem[c.stack_state] == 0


@pytest.mark.parametrize("fenced", [False, True])
def test_yield_retains_private_stack_and_nested_entry_fails_closed(fenced):
    c = stacked_config(fenced)
    owner = Machine(c, 19, yields=True)
    with pytest.raises(Yielded):
        owner.run()
    assert owner.mem[c.stack_state] == 1
    assert owner.mem[c.counter] == 19
    assert owner.events == ["actual_render"]
    private_before = {
        a: value
        for a, value in owner.mem.items()
        if c.target_stack[0] <= a < sum(c.target_stack)
    }
    nested = Machine(c)
    nested.mem = owner.mem
    nested.r = owner.r.copy()
    nested.entry = nested.snapshot()
    nested_sp = nested.low("sp")
    nested.run()
    assert nested.events == []
    assert nested.snapshot() == nested.entry
    assert nested.mem[c.stack_state] == 1  # the yielded owner still owns it
    assert nested.mem[c.stack_state + h.STACK_FAULT] == 1
    assert nested.mem[c.counter] == 19
    assert nested.mem[c.counter + h.COUNTER_FAULT] == 1
    assert nested.mem[c.stack_state + h.STACK_HIGHWATER] == 0x1234
    # Nested entry uses only its caller's 96-byte scratch frame. In particular
    # it never resets SP to the private top or overwrites the active bridge.
    allowed = {nested_sp - 96, nested_sp - 80, nested_sp - 32, nested_sp - 16}
    assert all(
        nested.mem[a] == value
        for a, value in private_before.items()
        if a not in allowed
    )
    assert not nested.deep_writes


@pytest.mark.parametrize("fenced", [False, True])
def test_private_stack_code_extent_and_frame_sizes(fenced):
    c = stacked_config(fenced)
    text = h.render(c, h.guard_expectations(c))
    before = text.split("jal actual_render\n", 1)[0]
    assert f"addiu $sp, $sp, -{h.PRE_FRAME}" in before
    assert h.PRE_FRAME == 96
    assert "%hi(target_stack_frame)" in before
    instructions = [
        line
        for line in text.splitlines()
        if not line.startswith(".") and not line.endswith(":")
    ]
    assert len(instructions) * 4 <= c.code_size == h.STACKED_CODE_SIZE


@pytest.mark.parametrize(
    "changes",
    [
        {"target_stack": None},
        {"stack_state": None},
        {"stack_state": True},
        {"stack_state": 0x1700004},
        {"stack_state": 0xA1700000},
        {"stack_state": 0x2000000},
        {"target_stack": [0x1800000, 0x10000]},
        {"target_stack": (0x1800000,)},
        {"target_stack": (True, 0x10000)},
        {"target_stack": (0x1800004, 0x10000)},
        {"target_stack": (0xA1800000, 0x10000)},
        {"target_stack": (0x1800000, True)},
        {"target_stack": (0x1800000, 0x3FF0)},
        {"target_stack": (0x1800000, 0x10010)},
        {"target_stack": (0x1800000, 0x4001)},
        {"target_stack": (0x1FFF000, 0x4000)},
        {"target_stack": (0x1400000, 0x10000)},
        {"target_stack": (0x1508000, 0x10000)},
        {"target_stack": (0x1600000, 0x10000)},
        {"target_stack": (0x320000, 0x10000)},
        {"target_stack": (0x1518000, 0x10000)},
        {"target_stack": (0x1700000, 0x10000)},
        {"stack_state": 0x1400100},
        {"stack_state": 0x1508030},
        {"stack_state": 0x1601000},
        {"stack_state": 0x320000},
        {"stack_state": 0x1518040},
        {"stack_state": 0x180FFF0},
        {"counter": 0x1400700},  # enlarged stacked code reservation matters too
    ],
)
def test_private_stack_rejects_invalid_or_overlapping_owned_memory(changes):
    with pytest.raises(ValueError):
        replace(stacked_config(True), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"fence_target": None},
        {"fence_state": None},
        {"fence_target": False},
        {"fence_target": 0xA1601800},
        {"fence_target": 0x1601802},
        {"fence_target": 0x1602000},
        {"fence_target": 0x1400010},
        {"fence_target": 0x1508030},
        {"call_site": 0x1601800},
        {"fence_state": 0},
        {"fence_state": True},
        {"fence_state": 0x1518041},
        {"fence_state": 0x2000000},
        {"fence_state": 0xA1518040},
        {"fence_state": 0x1400200},
        {"fence_state": 0x1508034},
        {"fence_state": 0x1601800},
        {"fence_state": 0x320004},
        {"counter": 0x1400300},
    ],
)
def test_fence_requires_paired_physical_safe_bindings(changes):
    with pytest.raises(ValueError):
        replace(fenced_config(), **changes)


def test_exact_call_and_delay_guards_required_without_mutation():
    c = config()
    for address in h.guard_expectations(c):
        words = h.guard_expectations(c)
        words[address] ^= 1
        with pytest.raises(ValueError):
            h.render(c, words)
        del words[address]
        with pytest.raises(ValueError):
            h.render(c, words)
    text = h.render(c, h.guard_expectations(c))
    assert text.count("jal ") == 1
    assert "jal actual_render\n" in text
    assert ".bss" not in text


@pytest.mark.parametrize(
    "changes",
    [
        {"call_site": 0},
        {"call_site": True},
        {"call_site": 0x1FFFFFC},
        {"call_site": 0x320002},
        {"call_site": 0x1601000},
        {"code": True},
        {"code": 0x1FFFFF0},
        {"code": 0x1400004},
        {"counter": 0x1400010},
        {"counter": 0x1FFFFF0 + 16},
        {"counter": 0x320000},
        {"code": 0x320000},
        {"actual_render": 0x1508030},
        {"actual_render": 0x1601002},
        {"actual_render": 0xA1601000},
        {"actual_render": 0x1602000},
        {"expected_call": h._jal(0x1700000)},
        {"expected_call": 0},
        {"expected_call": True},
        {"expected_call": 0x100000000},
        {"expected_delay": False},
        {"expected_delay": -1},
        {"expected_delay": 0x100000000},
        {"trusted_code": ()},
        {"trusted_code": ((0x1600000, 0x1000000),)},
        {"trusted_code": ((0x1600000, 0),)},
        {"trusted_code": ((0x1600000, True),)},
        {"trusted_code": ((0x1600000, 0x2000), (0x1601000, 0x1000))},
        {"trusted_code": ((0x1600000, 0x2000), (0x1400000, 0x1000))},
        {"trusted_code": ((0x1600000, 0x2000), (0x1508000, 0x1000))},
    ],
)
def test_reject_untrusted_targets_and_overlapping_or_nonphysical_extents(changes):
    with pytest.raises(ValueError):
        replace(config(), **changes)


ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@pytest.mark.skipif(not ASSEMBLER, reason="optional EE binutils not configured")
@pytest.mark.parametrize("shift", [0, 0x18000])
@pytest.mark.parametrize("fenced", [False, True])
@pytest.mark.parametrize("stacked", [False, True])
def test_real_assembler_link_and_four_byte_patch_without_counter_initialization(
    shift, fenced, stacked
):
    c = stacked_config(fenced) if stacked else fenced_config() if fenced else config()
    c = replace(c, code=c.code + shift, counter=c.counter + shift)
    words = h.guard_expectations(c)
    before = dict(words)
    built = h.build(c, words, assembler=ASSEMBLER)
    assert words == before
    assert len(built.patches) == 1
    patch = built.patches[0]
    assert patch.address == c.call_site
    assert patch.expected == c.expected_call
    assert patch.replacement == h._jal(built.linked.exports["hook_render"])
    assert words[c.call_site + 4] == c.expected_delay
    instructions = {}
    for payload in built.linked.payloads:
        assert (
            c.code
            <= payload.address
            <= payload.address + len(payload.data)
            <= c.code + c.code_size
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
    assert calls == [c.actual_render] + ([c.fence_target] if fenced else [])
    # Verify the paired HI16/LO16 relocation reconstructs the external counter.
    start = built.linked.exports["hook_render"]
    if not fenced and not stacked:
        high = instructions[start + 9 * 4] & 0xFFFF
        low = instructions[start + 10 * 4] & 0xFFFF
        assert (high << 16) + ((low ^ 0x8000) - 0x8000) == c.counter
    else:
        pointers = []
        for pc, word in instructions.items():
            if word >> 26 == 15:  # lui, paired with addiu of the same register
                low_word = instructions[pc + 4]
                assert low_word >> 26 == 9
                assert (
                    (word >> 16) & 31 == (low_word >> 21) & 31 == (low_word >> 16) & 31
                )
                low = low_word & 0xFFFF
                pointers.append(((word & 0xFFFF) << 16) + ((low ^ 0x8000) - 0x8000))
        expected = [c.fence_state, c.counter, c.counter] if fenced else [c.counter]
        if stacked:
            frame = sum(c.target_stack) - h.PRE_FRAME
            expected = (
                [c.stack_state, frame, frame] + expected + [c.stack_state, c.counter]
            )
        assert pointers == expected
