"""Offline protocol and emitted-assembly tests; no PINE or game execution."""

import os
import re
import shutil
import struct
import unittest
from typing import ClassVar

from injection.barriers import (
    CLEANUP_CALL,
    CLEANUP_TARGET,
    DEP_CALL,
    DEP_TARGET,
    EXIT_SITE,
    MAGIC,
    OFF,
    READY_SITE,
    SHEET_WAIT,
    STATE_SIZE,
    Config,
    Fault,
    Handshake,
    Phase,
    build,
    guard_expectations,
    initial_state,
    render,
)

CONFIG = Config(0x100000, 0x500000, 0x1400000, 0x1500000)
WORDS = {a: w for a, (w, _) in guard_expectations(CONFIG).items()}
ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


class ProtocolTests(unittest.TestCase):
    def test_one_pending_permit_once_and_explicit_ack(self):
        h = Handshake(generation=7)
        self.assertTrue(h.begin(0x123000, 0xB6))
        self.assertEqual(h.values["phase"], Phase.WAIT)
        self.assertFalse(h.tick())
        h.command(1, 7)
        self.assertTrue(h.tick())
        self.assertFalse(h.tick())
        self.assertEqual(h.original_calls, 1)
        self.assertEqual(h.values["complete_sequence"], 0)
        self.assertTrue(h.cleanup())
        self.assertEqual(h.values["complete_sequence"], 1)
        self.assertEqual(h.values["phase"], Phase.IDLE)
        with self.assertRaises(ValueError):
            h.acknowledge(2, 7)
        h.acknowledge(1, 7)
        self.assertTrue(h.begin(0x124000, 0xB7))
        self.assertEqual(h.values["sequence"], 2)

    def test_nested_and_unacknowledged_do_not_overwrite_identity(self):
        h = Handshake()
        h.begin(0x123000, 0xB6)
        self.assertFalse(h.begin(0x124000, 0xB7))
        self.assertEqual(h.values["request_sheet"], 0x123000)
        self.assertEqual(h.values["sequence"], 1)
        self.assertTrue(h.values["fault"] & Fault.NESTED)
        with self.assertRaises(ValueError):
            h.recover_wait(1, 1)
        h = Handshake()
        h.begin(0x123000, 0xB6)
        h.command(1, 1)
        h.tick()
        h.cleanup()
        self.assertFalse(h.begin(0x124000, 0xB7))
        self.assertEqual(h.values["fault"], Fault.UNACKNOWLEDGED)

    def test_unknown_epoch_abort_timeout_and_counter_overflow_fail_closed(self):
        for sequence, generation in ((2, 1), (1, 2), (0, 1)):
            h = Handshake()
            h.begin(0x123000, 0xB6)
            h.command(sequence, generation)
            self.assertFalse(h.tick())
            self.assertEqual(h.values["fault"], Fault.UNKNOWN_PERMIT)
            self.assertEqual(h.original_calls, 0)
        h = Handshake(wait_limit=2)
        h.begin(0x123000, 0xB6)
        h.tick()
        h.tick()
        h.command(1, 1)
        self.assertFalse(h.tick())  # timeout is not implicit permission
        self.assertEqual(h.values["fault"], Fault.TIMEOUT)
        h.recover_wait(1, 1)
        h.command(1, 1)
        self.assertTrue(h.tick())
        h = Handshake()
        h.begin(0x123000, 0xB6)
        h.command(1, 1, abort=True)
        self.assertFalse(h.tick())
        self.assertEqual(h.values["fault"], Fault.ABORT)
        h = Handshake(wait_limit=0)
        h.values["sequence"] = 0xFFFFFFFF
        self.assertFalse(h.begin(0x123000, 0xB6))
        self.assertEqual(h.values["fault"], Fault.OVERFLOW)
        self.assertEqual(h.values["sequence"], 0xFFFFFFFF)

    def test_layout_guards_and_allocations(self):
        self.assertEqual(len(initial_state()), STATE_SIZE)
        self.assertEqual(struct.unpack_from("<I", initial_state())[0], MAGIC)
        for bad in (0, -1, True, 0x100000000):
            with self.assertRaises(ValueError):
                initial_state(generation=bad)
        for address in WORDS:
            words = dict(WORDS)
            del words[address]
            with self.assertRaises(ValueError):
                render(CONFIG, words)
        words = dict(WORDS)
        words[CONFIG.g + READY_SITE + 4] ^= 1
        with self.assertRaises(ValueError):
            render(CONFIG, words)
        for args in (
            (0x100000, 0x500000, 0x1400000, 0x1400010),
            (0x100000, 0x500000, 0x1FFFFF0, 0x1500000),
            (0x100000, 0x500000, 0x1400000, 0x1FFFFF0),
        ):
            with self.assertRaises(ValueError):
                Config(*args)


class SourceMachine:
    """Small test-only interpreter for our emitted scalar/save instructions.

    Calls into the game are mocks. This does not emulate the game or PS2.
    Every register starts with nonzero upper bits to catch 64-bit-only saves.
    """

    aliases: ClassVar = dict(
        zip(
            (
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
            ),
            range(32),
        )
    )

    def __init__(self):
        self.instructions, self.labels, self.memory = [], {}, {}
        for line in render(CONFIG, WORDS).splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.instructions)
            elif not line.startswith(".") or line.startswith(".word"):
                self.instructions.append(line)
        self.r = [(i << 100) | (0x8000000000000000 + i) for i in range(32)]
        self.r[0] = 0
        self.r[29] = (29 << 100) | 0x1F00000
        self.r[4], self.r[5], self.r[6] = (4 << 100) | 0x123000, 0xB6, 0
        self.f = [0x3F000000 + i for i in range(32)]
        self.hi, self.lo, self.sa, self.fcsr = 0x1234 << 90, 0x5678 << 90, 27, 0x123
        self.events = []
        for i, value in enumerate(struct.unpack("<20I", initial_state(generation=7))):
            self.store(CONFIG.state + i * 4, value, 4)

    def reg(self, name):
        name = name.removeprefix("$")
        return int(name) if name.isdigit() else self.aliases[name]

    def store(self, address, value, size):
        for i in range(size):
            self.memory[address + i] = (value >> (i * 8)) & 255

    def load(self, address, size):
        return sum(self.memory.get(address + i, 0) << (i * 8) for i in range(size))

    def field(self, name, value=None):
        address = CONFIG.state + OFF[name]
        if value is not None:
            self.store(address, value, 4)
        return self.load(address, 4)

    def context(self):
        return list(self.r), list(self.f), self.hi, self.lo, self.sa, self.fcsr

    def execute(self, label, external, limit=6000):
        pc = self.labels[label]
        for _ in range(limit):
            line = self.instructions[pc]
            op, *args = re.split(r"[ ,]+", line)
            next_pc = pc + 1
            if op in ("b", "beq", "bne", "j", "jal", "jr"):
                self.assert_nop(pc)
                take = op not in ("beq", "bne") or (
                    (self.r[self.reg(args[0])] == self.r[self.reg(args[1])])
                    == (op == "beq")
                )
                next_pc = pc + 2
                if take:
                    target = args[-1]
                    if op == "jal":
                        self.r[31] = next_pc
                    if target in self.labels:
                        next_pc = self.labels[target]
                    else:
                        address = (
                            self.r[self.reg(target)] if op == "jr" else int(target, 0)
                        )
                        if external(address, self):
                            return
            elif op in ("nop", "sync"):
                pass
            elif op in ("sq", "sw", "lq", "lw", "swc1", "lwc1"):
                at, base = args[1].split("(")
                address = (self.r[self.reg(base[:-1])] & 0xFFFFFFFF) + int(at, 0)
                size = 16 if op in ("sq", "lq") else 4
                regs = self.f if op.endswith("c1") else self.r
                index = int(args[0][2:]) if op.endswith("c1") else self.reg(args[0])
                if op in ("sq", "sw", "swc1"):
                    self.store(address, regs[index], size)
                    if CONFIG.state <= address < CONFIG.state + STATE_SIZE:
                        self.events.append(
                            (address - CONFIG.state, regs[index] & 0xFFFFFFFF)
                        )
                else:
                    regs[index] = self.load(address, size)
                    if op == "lw" and regs[index] & 0x80000000:
                        regs[index] |= 0xFFFFFFFF00000000
            elif op in ("pmfhi", "pmflo", "mfsa"):
                self.r[self.reg(args[0])] = getattr(
                    self, {"pmfhi": "hi", "pmflo": "lo", "mfsa": "sa"}[op]
                )
            elif op in ("pmthi", "pmtlo", "mtsa"):
                setattr(
                    self,
                    {"pmthi": "hi", "pmtlo": "lo", "mtsa": "sa"}[op],
                    self.r[self.reg(args[0])],
                )
            elif op == "cfc1":
                self.r[self.reg(args[0])] = self.fcsr
            elif op == "ctc1":
                self.fcsr = self.r[self.reg(args[0])]
            elif op == "lui":
                self.r[self.reg(args[0])] = int(args[1], 0) << 16
            elif op == ".word":
                word = int(args[0], 0)
                opcode, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
                immediate = word & 65535
                if opcode == 0xF:
                    self.r[rt] = immediate << 16
                elif opcode == 0x23:
                    signed = immediate - 65536 if immediate & 0x8000 else immediate
                    value = self.load((self.r[rs] & 0xFFFFFFFF) + signed, 4)
                    self.r[rt] = value | (
                        0xFFFFFFFF00000000 if value & 0x80000000 else 0
                    )
                else:
                    raise AssertionError("unsafe replay instruction")
            elif op in ("ori", "addiu", "sltu", "or"):
                a = self.r[self.reg(args[1])]
                b = (
                    self.r[self.reg(args[2])]
                    if op in ("sltu", "or")
                    else int(args[2], 0)
                )
                result = (
                    a | b
                    if op in ("ori", "or")
                    else (int(a < b) if op == "sltu" else a + b)
                )
                self.r[self.reg(args[0])] = result & ((1 << 64) - 1)
            else:
                raise AssertionError(line)
            self.r[0] = 0
            pc = next_pc
        raise AssertionError("test instruction budget exhausted")

    def assert_nop(self, pc):
        assert self.instructions[pc + 1] == "nop", "unhandled test delay slot"


class EmittedProtocolTests(unittest.TestCase):
    def test_readiness_replays_both_branch_paths_and_exit_preserves_context(self):
        for value in (0, 42):
            m = SourceMachine()
            m.r[6] = 0x180000
            m.store(0x180000, value, 4)
            expected = m.context()
            expected[0][2] = value
            expected[0][3] = 0  # test's relocated LUI immediate

            def external(address, machine, value=value, expected=expected):
                target = CONFIG.g + (0x1756C if not value else READY_SITE + 12)
                self.assertEqual(address, target)
                self.assertEqual(machine.context(), expected)
                self.assertEqual(machine.field("gameplay_ready"), 1)
                return True

            m.execute("barrier_ready", external)
        m = SourceMachine()
        expected = m.context()
        m.field("gameplay_ready", 1)

        def exit_external(address, machine):
            self.assertEqual(address, CONFIG.g + 0xC0CD0)
            self.assertEqual(machine.context(), expected)
            self.assertEqual(machine.field("gameplay_ready"), 0)
            return True

        m.execute("barrier_exit", exit_external)

    def test_wait_restores_all_registers_and_calls_original_once(self):
        m = SourceMachine()
        expected = m.context()
        sleeps = []

        def external(address, machine):
            if address == CONFIG.m + SHEET_WAIT:
                sleeps.append(address)
                self.assertEqual(machine.field("phase"), Phase.WAIT)
                self.assertEqual(machine.field("request_sheet"), 0x123000)
                self.assertEqual(machine.field("request_segment"), 0xB6)
                for i in range(1, 32):
                    if i != 29:
                        machine.r[i] = i + 123
                machine.f = [0xDEAD0000 + i for i in range(32)]
                machine.hi, machine.lo, machine.sa, machine.fcsr = 1, 2, 3, 4
                machine.field("permit_generation", 7)
                machine.field("permit_sequence", 1)
                return False
            self.assertEqual(address, CONFIG.m + DEP_TARGET)
            self.assertEqual(machine.context(), expected)
            self.assertEqual(machine.field("phase"), Phase.RELEASING)
            self.assertEqual(machine.field("complete_sequence"), 0)
            return True

        m.execute("barrier_dependency", external)
        self.assertEqual(len(sleeps), 1)
        phase_event = m.events.index((OFF["phase"], Phase.WAIT))
        self.assertLess(m.events.index((OFF["request_sheet"], 0x123000)), phase_event)
        self.assertLess(m.events.index((OFF["request_segment"], 0xB6)), phase_event)

    def test_cleanup_preserves_original_results_and_publishes_after_return(self):
        m = SourceMachine()
        m.field("phase", Phase.RELEASING)
        m.field("sequence", 1)
        m.field("permit_sequence", 1)
        m.field("permit_generation", 7)
        entry = m.context()
        results = []

        def external(address, machine):
            if address == CONFIG.m + CLEANUP_TARGET:
                self.assertEqual(machine.field("complete_sequence"), 0)
                self.assertEqual(machine.r[4:8], entry[0][4:8])
                self.assertEqual(
                    machine.r[29] & 0xFFFFFFFF, (entry[0][29] & 0xFFFFFFFF) - 0x400
                )
                machine.r[2] = (99 << 100) | 0xABCD
                machine.r[8] = 0x999
                machine.f[3] = 0xDEAD
                machine.hi, machine.lo, machine.sa, machine.fcsr = 100, 101, 102, 103
                results.append(machine.context())
                return False
            self.assertEqual(address, entry[0][31])
            result = machine.context()
            wanted = results[0]
            wanted[0][29], wanted[0][31] = entry[0][29], entry[0][31]
            self.assertEqual(result, wanted)
            self.assertEqual(machine.field("complete_sequence"), 1)
            self.assertEqual(machine.field("complete_generation"), 7)
            self.assertEqual(machine.field("phase"), Phase.IDLE)
            return True

        m.execute("barrier_cleanup", external)
        self.assertLess(
            m.events.index((OFF["complete_generation"], 7)),
            m.events.index((OFF["phase"], 0)),
        )

    def test_emitted_timeout_unknown_and_overflow_do_not_call_original(self):
        for mode in ("timeout", "unknown", "overflow", "nested", "abort"):
            m = SourceMachine()
            if mode == "timeout":
                m.field("wait_limit", 1)
            elif mode == "overflow":
                m.field("sequence", 0xFFFFFFFF)
            elif mode == "nested":
                m.field("phase", Phase.WAIT)
                m.field("request_sheet", 0x555000)
            sleeps = []

            def external(address, machine, sleeps=sleeps, mode=mode):
                self.assertEqual(address, CONFIG.m + SHEET_WAIT)
                sleeps.append(address)
                if mode == "unknown" and len(sleeps) == 1:
                    machine.field("permit_sequence", 999)
                    machine.field("permit_generation", 7)
                if mode == "abort" and len(sleeps) == 1:
                    machine.field("abort_sequence", 1)
                    machine.field("abort_generation", 7)
                return len(sleeps) == 3

            m.execute("barrier_dependency", external)
            expected = {
                "timeout": Fault.TIMEOUT,
                "unknown": Fault.UNKNOWN_PERMIT,
                "overflow": Fault.OVERFLOW,
                "nested": Fault.NESTED,
                "abort": Fault.ABORT,
            }[mode]
            self.assertEqual(m.field("fault"), expected)
            if mode == "nested":
                self.assertEqual(m.field("request_sheet"), 0x555000)


@unittest.skipUnless(ASSEMBLER, "set SOTC_EE_AS to the EE assembler")
class AssemblerTests(unittest.TestCase):
    def test_real_assembly_guarded_patches_and_relocated_branch(self):
        result = build(CONFIG, WORDS, assembler=ASSEMBLER)
        self.assertEqual(len(result.patches), 5)
        by_address = {p.address: p for p in result.patches}
        self.assertNotIn(CONFIG.m + DEP_CALL + 4, by_address)
        self.assertNotIn(CONFIG.m + CLEANUP_CALL + 4, by_address)
        self.assertNotIn(CONFIG.g + EXIT_SITE + 4, by_address)
        self.assertEqual(by_address[CONFIG.g + READY_SITE + 4].replacement, 0)
        text = next(p for p in result.linked.payloads if p.section == ".text")
        words = list(struct.unpack(f"<{len(text.data) // 4}I", text.data))
        self.assertNotIn(WORDS[CONFIG.g + READY_SITE + 4], words)
        # Branch targets are local helper labels, not copied PC-relative game words.
        self.assertIn(f"j 0x{CONFIG.g + 0x1756C:x}", result.assembly)
        self.assertIn(f"j 0x{CONFIG.g + READY_SITE + 12:x}", result.assembly)
        self.assertIn(0x08000000 | ((CONFIG.m + DEP_TARGET) >> 2), words)
        self.assertIn(0x0C000000 | ((CONFIG.m + CLEANUP_TARGET) >> 2), words)
        for i in range(1, 32):
            if i != 29:
                self.assertIn(f"sq ${i}, {i * 16}($sp)", result.assembly)
                self.assertIn(f"lq ${i}, {i * 16}($sp)", result.assembly)
        for i in range(32):
            self.assertIn(f"swc1 $f{i}, {0x200 + 4 * i}($sp)", result.assembly)
            self.assertIn(f"lwc1 $f{i}, {0x200 + 4 * i}($sp)", result.assembly)
        self.assertIn("pmfhi $k0", result.assembly)
        self.assertIn("pmthi $k0", result.assembly)


if __name__ == "__main__":
    unittest.main()
