"""Synthetic emitted-code execution only: these are not scheduler qualification."""

import os
import re
import shutil
import struct
import unittest
from typing import ClassVar

from injection.resource_gate import (
    CODE_SIZE,
    COMPLETE,
    ENTRY,
    FIELDS,
    MAGIC,
    OFF,
    SHEET_WAIT,
    STATE_SIZE,
    Config,
    Phase,
    build,
    guard_expectations,
    initial_state,
    render,
)

CONFIG = Config(0x500000, 0x1400000, 0x1500000, 0x100800)
WORDS = {a: w for a, (w, _) in guard_expectations(CONFIG).items()}
WORDS[CONFIG.m + ENTRY + 8] |= 0x1234
WORDS[CONFIG.m + ENTRY + 12] |= 0x5678
WORDS[CONFIG.m + COMPLETE + 4] |= 0xA560
ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


class Machine:
    aliases: ClassVar = dict(
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

    def __init__(self, op=1):
        self.ins, self.labels, self.mem = [], {}, {}
        for line in render(CONFIG, WORDS).splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.ins)
            elif not line.startswith(".") or line.startswith(".word"):
                self.ins.append(line)
        self.r = [(i << 100) | i for i in range(32)]
        self.r[0] = 0
        self.r[29] = (29 << 100) | 0x1F00000
        self.r[18] = (18 << 100) | 0x1800000
        self.r[5] = op
        self.f = [0x3F000000 + i for i in range(32)]
        self.hi, self.lo, self.sa, self.fcsr = 1 << 110, 2 << 110, 17, 42
        for i, value in enumerate(struct.unpack("<16I", initial_state(generation=7))):
            self.store(CONFIG.state + i * 4, value, 4)
        for offset, value in ((0, op), (8, 0x123000), (12, 0xB6)):
            self.store(0x1800000 + offset, value, 4)
        self.reads, self.events = [], []

    def reg(self, s):
        s = s.lstrip("$")
        return int(s) if s.isdigit() else self.aliases[s]

    def store(self, a, v, n):
        for i in range(n):
            self.mem[a + i] = (v >> (8 * i)) & 255

    def load(self, a, n):
        return sum(self.mem.get(a + i, 0) << (8 * i) for i in range(n))

    def field(self, name, value=None):
        a = CONFIG.state + OFF[name]
        if value is not None:
            self.store(a, value, 4)
        return self.load(a, 4)

    def context(self):
        return self.r[:], self.f[:], self.hi, self.lo, self.sa, self.fcsr

    def clobber(self):
        # A mock callee may use its argument area but not caller-owned stack.
        sp = self.r[29] & 0xFFFFFFFF
        self.store(sp, (1 << 256) - 1, 32)
        for i in range(1, 32):
            if i != 29:
                self.r[i] = (i << 110) | 0xBAD
        self.f = [i + 100 for i in range(32)]
        self.hi, self.lo, self.sa, self.fcsr = 5, 6, 7, 8

    def run(self, label, external, limit=8000):
        pc = self.labels[label]
        for _ in range(limit):
            op, *a = re.split(r"[ ,]+", self.ins[pc])
            nxt = pc + 1
            if op in ("b", "beq", "bne", "j", "jal"):
                assert self.ins[pc + 1] == "nop"
                nxt = pc + 2
                take = op not in ("beq", "bne") or (
                    (self.r[self.reg(a[0])] == self.r[self.reg(a[1])]) == (op == "beq")
                )
                if take:
                    if op == "jal":
                        self.r[31] = nxt
                    target = a[-1]
                    if target in self.labels:
                        nxt = self.labels[target]
                    elif external(int(target, 0), self):
                        return
            elif op in ("nop", "sync"):
                pass
            elif op in ("sq", "lq", "sw", "lw", "swc1", "lwc1"):
                off, base = a[1].split("(")
                address = (self.r[self.reg(base[:-1])] & 0xFFFFFFFF) + int(off, 0)
                n = 16 if op in ("sq", "lq") else 4
                regs = self.f if op.endswith("c1") else self.r
                i = int(a[0][2:]) if op.endswith("c1") else self.reg(a[0])
                if op in ("sq", "sw", "swc1"):
                    self.store(address, regs[i], n)
                    self.events.append((address, regs[i] & 0xFFFFFFFF))
                else:
                    self.reads.append((address, n))
                    regs[i] = self.load(address, n)
                    if op == "lw" and regs[i] & 0x80000000:
                        regs[i] |= 0xFFFFFFFF00000000
            elif op in ("pmfhi", "pmflo", "mfsa", "cfc1"):
                attr = {"pmfhi": "hi", "pmflo": "lo", "mfsa": "sa", "cfc1": "fcsr"}[op]
                self.r[self.reg(a[0])] = getattr(self, attr)
            elif op in ("pmthi", "pmtlo", "mtsa", "ctc1"):
                attr = {"pmthi": "hi", "pmtlo": "lo", "mtsa": "sa", "ctc1": "fcsr"}[op]
                setattr(self, attr, self.r[self.reg(a[0])])
            elif op == ".word":
                word = int(a[0], 0)
                code, rs, rt, imm = (
                    word >> 26,
                    word >> 21 & 31,
                    word >> 16 & 31,
                    word & 65535,
                )
                if code == 15:
                    self.r[rt] = imm << 16
                elif code == 11:
                    self.r[rt] = int((self.r[rs] & ((1 << 64) - 1)) < imm)
                else:
                    raise AssertionError("unexpected replay")
            elif op == "lui":
                self.r[self.reg(a[0])] = int(a[1], 0) << 16
            elif op in ("ori", "andi", "addiu", "sltu", "or"):
                x = self.r[self.reg(a[1])] & ((1 << 64) - 1)
                y = self.r[self.reg(a[2])] if op in ("or", "sltu") else int(a[2], 0)
                v = (
                    (x | y)
                    if op in ("ori", "or")
                    else (
                        (x & y)
                        if op == "andi"
                        else (int(x < y) if op == "sltu" else x + y)
                    )
                )
                self.r[self.reg(a[0])] = v & ((1 << 64) - 1)
            else:
                raise AssertionError(op)
            self.r[0] = 0
            pc = nxt
        raise AssertionError("instruction budget exhausted")


class GateTests(unittest.TestCase):
    def test_missing_permit_keeps_sleeping_without_timeout_or_completion(self):
        m = Machine()
        original_sp = m.r[29] & 0xFFFFFFFF
        parameters = bytes(range(128))
        for i, value in enumerate(parameters):
            m.store(original_sp + i, value, 1)
        sleeps = []

        def external(address, machine):
            self.assertEqual(address, CONFIG.m + SHEET_WAIT)
            self.assertEqual(machine.field("phase"), Phase.WAIT)
            self.assertEqual(machine.field("fault"), 0)
            self.assertEqual(machine.field("complete_sequence"), 0)
            sleeps.append(address)
            machine.clobber()
            return len(sleeps) == 100

        m.run("resource_gate_entry", external, limit=25000)
        self.assertEqual(len(sleeps), 100)
        self.assertEqual(
            bytes(m.load(original_sp + i, 1) for i in range(128)), parameters
        )

    def test_corrupt_completion_cannot_publish_partial_completion(self):
        m = Machine()
        for name, value in (
            ("phase", Phase.RELEASING),
            ("request", 0x1800000),
            ("sequence", 1),
            ("permit_sequence", 1),
            ("permit_generation", 8),
        ):
            m.field(name, value)
        sleeps = []

        def external(address, machine):
            self.assertEqual(address, CONFIG.m + SHEET_WAIT)
            sleeps.append(address)
            return len(sleeps) == 2

        m.run("resource_gate_complete", external)
        self.assertNotEqual(m.field("fault"), 0)
        self.assertEqual(m.field("complete_sequence"), 0)
        self.assertEqual(m.field("complete_generation"), 0)
        self.assertEqual(m.field("phase"), Phase.RELEASING)

    def test_destructive_ops_wait_then_resume_exact_context_and_complete(self):
        for op in (1, 3, 5, 6):
            with self.subTest(op=op):
                m = Machine(op)
                original = m.context()
                sleeps = []

                def external(address, machine, sleeps=sleeps, op=op, original=original):
                    if address == CONFIG.m + SHEET_WAIT:
                        sleeps.append(address)
                        self.assertEqual(machine.field("phase"), Phase.WAIT)
                        self.assertEqual(machine.field("request"), 0x1800000)
                        self.assertEqual(machine.field("sheet"), 0x123000)
                        self.assertEqual(machine.field("segment"), 0xB6)
                        self.assertEqual(machine.field("op"), op)
                        self.assertEqual(machine.field("ready"), 0)
                        machine.clobber()
                        machine.field("permit_sequence", 1)
                        machine.field("permit_generation", 7)
                        return False
                    self.assertEqual(address, CONFIG.m + ENTRY + 12)
                    expected = (original[0][:], *original[1:])
                    expected[0][2:4] = [1, 0x12340000]
                    self.assertEqual(machine.context(), expected)
                    self.assertEqual(machine.field("phase"), Phase.RELEASING)
                    self.assertEqual(machine.field("complete_sequence"), 0)
                    return True

                m.run("resource_gate_entry", external)
                self.assertEqual(len(sleeps), 1)
                reads = {
                    a - 0x1800000 for a, _ in m.reads if 0x1800000 <= a < 0x1800100
                }
                self.assertEqual(reads, {0, 8, 12})
                # Model the original JAL/delay slot: s2 remains the active request,
                # a0 contains the loaded semaphore and ra is E37A8.
                m.r[4], m.r[31] = 123, CONFIG.m + COMPLETE + 8
                before = m.context()
                calls = []

                def wait_sema(address, machine, calls=calls, before=before):
                    calls.append(address)
                    self.assertEqual(address, CONFIG.expected_wait_sema)
                    self.assertEqual(machine.context(), before)
                    self.assertEqual(machine.field("phase"), Phase.IDLE)
                    self.assertEqual(machine.field("complete_sequence"), 1)
                    self.assertEqual(machine.field("complete_generation"), 7)
                    machine.clobber()  # no helper runs after this tail-call
                    return True

                m.run("resource_gate_complete", wait_sema)
                self.assertEqual(calls, [CONFIG.expected_wait_sema])
                self.assertEqual(m.r[2], (2 << 110) | 0xBAD)
                # The next request gets a strictly increasing sequence.
                m.r[18], m.r[5] = 0x1800000, op
                m.run("resource_gate_entry", lambda a, _: a == CONFIG.m + SHEET_WAIT)
                self.assertEqual(m.field("sequence"), 2)

    def test_non_destructive_and_out_of_range_replay_both_lui_paths(self):
        for op in (0, 2, 4, 7, 8, 9, 10, 11, 12, 13, 0xFFFFFFFF):
            m = Machine(op)
            m.r[18] = 3  # bypass must not read a request or require valid state
            m.field("magic", 0)
            before = m.context()

            def external(address, machine, op=op, before=before):
                self.assertEqual(
                    address, CONFIG.m + (ENTRY + 12 if op < 13 else 0xE3788)
                )
                expected = (before[0][:], *before[1:])
                expected[0][2:4] = [int(op < 13), 0x12340000]
                self.assertEqual(machine.context(), expected)
                self.assertEqual(machine.field("sequence"), 0)
                return True

            m.run("resource_gate_entry", external)
            self.assertFalse(
                any(CONFIG.state <= a < CONFIG.state + STATE_SIZE for a, _ in m.events)
            )

    def test_sticky_failures_never_release(self):
        for mode in (
            "wrong_seq",
            "wrong_gen",
            "magic_loss",
            "phase_loss",
            "gen_loss",
            "request_loss",
            "nested",
            "overflow",
            "bad_pointer",
            "mismatched_op",
        ):
            with self.subTest(mode=mode):
                m = Machine()
                if mode == "nested":
                    m.field("phase", Phase.WAIT)
                    m.field("request", 0x888000)
                elif mode == "overflow":
                    m.field("sequence", 0xFFFFFFFF)
                elif mode == "bad_pointer":
                    m.r[18] = 0x1FFFFFC
                elif mode == "mismatched_op":
                    m.store(0x1800000, 3, 4)
                sleeps = []

                def external(address, machine, sleeps=sleeps, mode=mode):
                    self.assertEqual(address, CONFIG.m + SHEET_WAIT)
                    sleeps.append(address)
                    if len(sleeps) == 1:
                        if mode.startswith("wrong_"):
                            machine.field(
                                "permit_sequence", 2 if mode == "wrong_seq" else 1
                            )
                            machine.field(
                                "permit_generation", 8 if mode == "wrong_gen" else 7
                            )
                        elif mode.endswith("_loss"):
                            machine.field(
                                {
                                    "magic_loss": "magic",
                                    "phase_loss": "phase",
                                    "gen_loss": "generation",
                                    "request_loss": "request",
                                }[mode],
                                0,
                            )
                    elif len(sleeps) == 2:
                        # A later correct permit cannot heal the sticky fault.
                        machine.field("permit_sequence", 1)
                        machine.field("permit_generation", 7)
                    return len(sleeps) == 3

                m.run("resource_gate_entry", external)
                self.assertNotEqual(m.field("fault"), 0)
                self.assertEqual(m.field("complete_sequence"), 0)
                if mode == "nested":
                    self.assertEqual(m.field("request"), 0x888000)
                if mode == "overflow":
                    self.assertEqual(m.field("sequence"), 0xFFFFFFFF)

    def test_unrelated_completion_does_not_clear_pending(self):
        for phase in (Phase.IDLE, Phase.WAIT, Phase.RELEASING):
            m = Machine()
            m.field("phase", phase)
            m.field("request", 0x888000)
            before = bytes(m.load(CONFIG.state + i, 1) for i in range(STATE_SIZE))
            context = m.context()

            def external(address, machine, context=context):
                self.assertEqual(address, CONFIG.expected_wait_sema)
                self.assertEqual(machine.context(), context)
                return True

            m.run("resource_gate_complete", external)
            self.assertEqual(
                bytes(m.load(CONFIG.state + i, 1) for i in range(STATE_SIZE)), before
            )

    def test_cancellation_guard_branch_skips_entry(self):
        # Execute the guarded beql semantics: only noncancelled requests take
        # E3350 and execute its delay-slot load. Cancelled requests skip both.
        branch = WORDS[CONFIG.m + 0xE3338]
        self.assertEqual(branch >> 26, 0x14)
        target = CONFIG.m + 0xE333C + 4 * (branch & 65535)
        self.assertEqual(target, CONFIG.m + ENTRY)
        for cancelled in (False, True):
            pc = target if not cancelled else CONFIG.m + 0xE3340
            self.assertEqual(pc == CONFIG.m + ENTRY, not cancelled)
        skip = WORDS[CONFIG.m + 0xE3344]
        self.assertEqual(CONFIG.m + 0xE3348 + 4 * (skip & 65535), CONFIG.m + 0xE3798)

    def test_layout_guards_and_extent_rejection(self):
        self.assertEqual(len(initial_state()), STATE_SIZE)
        self.assertEqual(struct.unpack("<16I", initial_state())[0], MAGIC)
        self.assertEqual(len(FIELDS), 15)
        for address in WORDS:
            bad = WORDS.copy()
            del bad[address]
            with self.assertRaises(ValueError):
                render(CONFIG, bad)
        for args in (
            (CONFIG.m, CONFIG.m + ENTRY, CONFIG.state, CONFIG.expected_wait_sema),
            (CONFIG.m, CONFIG.code, CONFIG.code + 16, CONFIG.expected_wait_sema),
            (CONFIG.m, 0x1FFFFF0, CONFIG.state, CONFIG.expected_wait_sema),
            (CONFIG.m, CONFIG.code, CONFIG.state, CONFIG.code),
        ):
            with self.assertRaises(ValueError):
                Config(*args)
        for generation in (0, -1, True, 0x100000000):
            with self.assertRaises(ValueError):
                initial_state(generation=generation)

    @unittest.skipUnless(ASSEMBLER, "EE assembler unavailable")
    def test_real_assembler_and_exact_patch_seams(self):
        result = build(CONFIG, WORDS, assembler=ASSEMBLER)
        self.assertEqual(
            {p.address for p in result.patches},
            {CONFIG.m + ENTRY, CONFIG.m + ENTRY + 4, CONFIG.m + COMPLETE},
        )
        self.assertEqual(result.patches[1].replacement, 0)
        self.assertTrue(
            all(
                CONFIG.code
                <= p.address
                < p.address + len(p.data)
                <= CONFIG.code + CODE_SIZE
                for p in result.linked.payloads
                if p.data
            )
        )
        for i in range(1, 32):
            if i != 29:
                self.assertIn(f"sq ${i}, {i * 16}($sp)", result.assembly)
                self.assertIn(f"lq ${i}, {i * 16}($sp)", result.assembly)


if __name__ == "__main__":
    unittest.main()
