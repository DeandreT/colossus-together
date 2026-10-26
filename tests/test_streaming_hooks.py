"""Offline execution of real EE hook bytes; original XFF is read-only evidence."""

import struct
import unittest
from dataclasses import replace
from unittest.mock import patch

import test_streaming_native as base
from interrupt_model import InterruptModel

from streaming import hooks as h
from local_config import original_file

AS = base.AS
ORIGINAL = original_file("GAMECORE.XFF")


def config():
    return h.Config(
        g=0x300000, code=0x1400000, context=0x1500000, context_size=0x1000,
        callback_gp=0x141D70,
        callbacks={name: 0x1600000 + i * 0x100 for i, name in enumerate(sorted(h.CALLBACKS))},
        originals={**{name: 0x300000 + off for name, off in h.ORIGINAL_OFFSETS.items()},
                   "ios_free": 0x1A00000},
        trusted_code=((0x300038, 0x130000), (0x1600000, 0x10000), (0x1A00000, 0x10000)),
    )


class Machine(InterruptModel, base.Machine):
    def __init__(self, c, linked, symbol, args=()):
        super().__init__(c, linked, symbol, args)
        self.hi = (0xFFAA << 96) | 0x123456789
        self.lo = (0xBBCC << 96) | 0x234567890
        self.sa, self.fcsr = 17, 0x10203
        self.fprs = [0x12340000 + i for i in range(32)]
        self.before = self.snapshot()
        self.native_post = None
        self.handlers = {}
        self.results = {}
        self.trace = []
        self.minimum_sp = self.low(29)

    def snapshot(self):
        return self.reg.copy(), self.hi, self.lo, self.sa, self.fcsr, self.fprs.copy()

    def compare(self, case, wanted, except_regs=()):
        actual = self.snapshot()
        for i in range(32):
            if i not in except_regs and not (
                self.interrupt_at is not None and i in (26, 27)
            ):
                case.assertEqual(actual[0][i], wanted[0][i], f"GPR {i}")
        case.assertEqual(actual[1:], wanted[1:])

    def clobber(self, native=False):
        saved = set(range(16, 24)) | {28, 29, 30, 31} if native else {29}
        for i in range(1, 32):
            if i not in saved:
                self.reg[i] = (0xFACE0000 + i) << 96 | 0xAAA000 + i
        self.hi, self.lo, self.sa, self.fcsr = (1 << 127) + 11, (1 << 126) + 12, 23, 0x123456
        self.fprs = [0x87650000 + i for i in range(32)]
        self.write(self.low(29), bytes([0xCC]) * 64)

    def external(self):
        reverse = {v: ("cb_" + k) for k, v in self.c.callbacks.items()}
        reverse.update({v: ("orig_" + k) for k, v in self.c.originals.items()})
        name = reverse[self.pc]
        ret = self.low(31)
        self.events.append(name)
        if name.startswith("cb_"):
            assert self.low(4) == self.c.context
            assert self.low(28) == self.c.callback_gp
        if name in self.handlers:
            self.handlers[name](self)
        self.clobber(native=name.startswith("orig_"))
        self.reg[2] = self.results.get(name, 0x12345678)
        if name in ("orig_chip", "orig_maintenance"):
            self.native_post = self.snapshot()
        self.pc = ret

    def execute(self, pc):
        self.boundary(f"{pc:#x}")
        self.trace.append(pc)
        word = self.word(pc)
        op, rs, rt = word >> 26, word >> 21 & 31, word >> 16 & 31
        rd, sa, fn = word >> 11 & 31, word >> 6 & 31, word & 63
        if op in (2, 3):
            if op == 3:
                self.set(31, pc + 8)
            return (pc + 4 & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
        if op == 0x1C and fn == 9 and sa in (8, 9):
            self.set(rd, self.hi if sa == 8 else self.lo)
        elif op == 0x1C and fn == 0x29 and sa in (8, 9):
            if sa == 8:
                self.hi = self.reg[rs]
            else:
                self.lo = self.reg[rs]
        elif op == 0 and fn == 0x28:
            self.set(rd, self.sa)
        elif op == 0 and fn == 0x29:
            self.sa = self.low(rs)
        elif op == 0 and fn == 0x2D:
            self.set(rd, self.reg[rs] + self.reg[rt])
        elif op == 17 and rs in (2, 6):
            assert rd == 31
            if rs == 2:
                self.set(rt, self.fcsr)
            else:
                self.fcsr = self.low(rt)
        elif op in (49, 57):
            imm = (word & 65535) - (65536 if word & 32768 else 0)
            addr = self.low(rs) + imm
            if op == 49:
                self.fprs[rt] = self.word(addr)
            else:
                self.write(addr, struct.pack("<I", self.fprs[rt]))
        elif op == 0x3F:  # SD: native displaced unloader prologue
            imm = (word & 65535) - (65536 if word & 32768 else 0)
            self.write(self.low(rs) + imm, (self.reg[rt] & ((1 << 64) - 1)).to_bytes(8, "little"))
        else:
            return super().execute(pc)
        return None

    def run(self, stop=None):
        targets = set(self.c.callbacks.values()) | set(self.c.originals.values())
        stop = self.before[0][31] & 0xFFFFFFFF if stop is None else stop
        for _ in range(10000):
            self.minimum_sp = min(self.minimum_sp, self.low(29))
            if self.pc == stop:
                return
            if self.pc in targets:
                self.external()
                continue
            dest = self.execute(self.pc)
            if dest is None:
                self.pc += 4
            else:
                assert self.execute(self.pc + 4) is None
                self.pc = dest
        raise AssertionError("hook did not return")


class HookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not AS.exists():
            raise unittest.SkipTest("real EE assembler not available")
        cls.c = config()
        cls.linked = h._assemble(cls.c, h.render(cls.c), AS)

    def test_begin_original_first_preserves_actual_post_state(self):
        m = Machine(self.c, self.linked, "hook_begin")
        args = (0x1700000, m.start_sp, m.start_sp + 4, 4, 5, 6, 7, 8)
        for i, value in enumerate(args):
            m.reg[4 + i] = value
        m.before = m.snapshot()

        def chip(cpu):
            # The pre-call copy scratch must not replace the original AT value,
            # including its upper lanes, when entering the real callee.
            self.assertEqual(cpu.reg[1], cpu.before[0][1])
            self.assertEqual([cpu.low(i) for i in range(4, 12)], list(args))
            self.assertEqual(cpu.low(29), cpu.start_sp - h.PRE_FRAME)
            self.assertEqual(cpu.read(cpu.low(29), 64), bytes([0xA7]) * 64)
            cpu.write(args[1], struct.pack("<I", 31))
            cpu.write(args[2], struct.pack("<I", 29))

        def begin(cpu):
            self.assertEqual(cpu.events, ["orig_chip", "cb_begin"])
            self.assertEqual(cpu.word(m.start_sp), 31)
            self.assertEqual(cpu.word(m.start_sp + 4), 29)

        m.handlers = {"orig_chip": chip, "cb_begin": begin}
        m.run()
        m.compare(self, m.native_post, except_regs=(29, 31))
        self.assertEqual(m.reg[29], m.before[0][29])
        self.assertEqual(m.reg[31], m.before[0][31])
        self.assertEqual(m.start_sp - m.minimum_sp, h.PRE_FRAME + h.FULL_FRAME)

    def test_interrupts_during_begin_and_submit(self):
        # execute() is called for individual instructions, including delay slots.
        # Exercise both full capture/restore and the pre-capture argument copies.
        with patch.object(Machine, "interrupt_at", "all"):
            self.test_begin_original_first_preserves_actual_post_state()
            self.test_submit_ten_words_no_automatic_original()
            self.test_predicate_result_only()

    def test_interrupt_mutation_detects_begin_and_submit_scratch(self):
        old = h.render(self.c).replace("$at", "$k0").replace("$t9", "$k1")
        linked = h._assemble(self.c, old, AS)
        with patch.object(self, "linked", linked), patch.object(Machine, "interrupt_at", "all"):
            with self.assertRaises(AssertionError):
                self.test_begin_original_first_preserves_actual_post_state()
            with self.assertRaises(AssertionError):
                self.test_submit_ten_words_no_automatic_original()

    def interrupt_case(self, symbol, interrupt_at, linked=None):
        m = Machine(self.c, linked or self.linked, symbol, tuple(range(10, 18)))
        m.interrupt_at = interrupt_at
        if symbol == "hook_begin":
            def chip(cpu):
                for i in range(1, 32):
                    if i not in (26, 27, 29, 31):
                        self.assertEqual(cpu.reg[i], cpu.before[0][i], f"input GPR {i}")
                self.assertEqual(cpu.read(cpu.low(29), 64), bytes([0xA7]) * 64)
            m.handlers["orig_chip"] = chip
        else:
            m.write(m.start_sp, struct.pack("<I", 18))
            m.write(m.start_sp + 8, struct.pack("<I", 19))

            def submit(cpu):
                self.assertEqual(struct.unpack("<10I", cpu.read(cpu.low(5), 40)),
                                 tuple(range(10, 20)))
            m.handlers["cb_submit"] = submit
        m.run()
        if symbol == "hook_begin":
            m.compare(self, m.native_post, except_regs=(29, 31))
            self.assertEqual(m.reg[29], m.before[0][29])
            self.assertEqual(m.reg[31], m.before[0][31])
        else:
            m.compare(self, m.before)
        return m

    def test_every_begin_and_submit_instruction_boundary(self):
        for symbol in ("hook_begin", "hook_submit"):
            baseline = self.interrupt_case(symbol, None)
            for index in range(len(baseline.boundaries)):
                with self.subTest(symbol=symbol, boundary=index):
                    self.interrupt_case(symbol, index)

    def test_interrupt_mutations_isolate_precall_and_stack_dereference(self):
        source = h.render(self.c)
        precall, rest = source.split("jal orig_chip", 1)
        old_begin = precall.replace("$at", "$k0") + "jal orig_chip" + rest
        stack_copy = (f"lq $at,{h.SAVED_SP}($sp)\n"
                      "lw $t9,0($at)\n"
                      f"sw $t9,{h.BATCH_ARGS + 32}($sp)\n"
                      "lw $t9,8($at)\n"
                      f"sw $t9,{h.BATCH_ARGS + 36}($sp)")
        self.assertIn(stack_copy, source)
        old_submit = source.replace(stack_copy, stack_copy.replace("$at", "$k0")
                                    .replace("$t9", "$k1"))
        for symbol, text in (("hook_begin", old_begin), ("hook_submit", old_submit)):
            linked = h._assemble(self.c, text, AS)
            with self.subTest(symbol=symbol), self.assertRaises(AssertionError):
                self.interrupt_case(symbol, "all", linked)

    def test_submit_ten_words_no_automatic_original(self):
        for site in (0x20CB8, 0x20DB8, 0x20FE4):
            m = Machine(self.c, self.linked, "hook_submit", tuple(range(10, 18)))
            m.reg[30 if site == 0x20FE4 else 22] = 18
            m.reg[23 if site == 0x20FE4 else 21] = 19
            m.before = m.snapshot()
            m.write(m.start_sp, struct.pack("<I", 18))
            call = self.c.g + site
            m.write(call, struct.pack("<II", h._jump(self.linked.exports["hook_submit"], True),
                                      h.guard_expectations(self.c)[call + 4]))
            m.pc = call

            def submit(cpu):
                address = cpu.low(5)
                self.assertEqual(struct.unpack("<10I", cpu.read(address, 40)), tuple(range(10, 20)))
            m.handlers["cb_submit"] = submit
            m.run(stop=call + 8)
            self.assertEqual(m.events, ["cb_submit"], hex(site))
            wanted = (m.before[0].copy(),) + m.before[1:]
            wanted[0][31] = call + 8
            m.compare(self, wanted)
            self.assertEqual(m.trace.count(call + 4), 1)
            self.assertEqual(m.word(m.start_sp), 18)
            self.assertEqual(m.word(m.start_sp + 8), 19)

    def test_predicate_result_only(self):
        for result in (0, 1):
            m = Machine(self.c, self.linked, "hook_predicate", (17, 13, 1, 41, 42, 43, 44, 45))
            m.results["cb_predicate"] = result

            def predicate(cpu):
                self.assertEqual([cpu.low(i) for i in range(5, 12)],
                                 [17, 13, 1, 41, 42, 43, 44])
            m.handlers["cb_predicate"] = predicate
            m.run()
            self.assertEqual(m.events, ["cb_predicate"])
            self.assertEqual(m.low(2), result)
            m.compare(self, m.before, except_regs=(2,))

    def test_refresh_then_displaced_prologue(self):
        m = Machine(self.c, self.linked, "hook_refresh", tuple(range(1, 9)))
        m.run(stop=self.c.g + 0x21028)
        self.assertEqual(m.events, ["cb_refresh_keep"])
        m.compare(self, m.before, except_regs=(29,))
        self.assertEqual(m.low(29), m.start_sp - 96)
        self.assertEqual(int.from_bytes(m.read(m.low(29) + 16, 8), "little"),
                         m.before[0][18] & ((1 << 64) - 1))
        self.assertEqual(m.start_sp - m.minimum_sp, h.FULL_FRAME)

    def test_eviction_true_skips_both_false_runs_original(self):
        for i, (site, nxt) in enumerate(h.EVICTIONS):
            for keep in (0, 1):
                m = Machine(self.c, self.linked, f"hook_keep_{i}")
                record = 0x1700000
                m.reg[16] = record
                m.before = m.snapshot()
                m.write(record, struct.pack("<7I", 19, 23, 1, 0, 0, 0, 0x1710000))
                guards = h.guard_expectations(self.c)
                for address in range(self.c.g + site + 8, self.c.g + nxt, 4):
                    m.write(address, struct.pack("<I", guards[address]))
                m.results["cb_keep"] = keep

                def check(cpu, record=record):
                    self.assertEqual(cpu.low(5), record)
                def unlink(cpu, record=record, site=site):
                    self.assertEqual(cpu.low(4), record)
                    self.assertEqual(cpu.low(31), self.c.g + site + 8)
                def unload(cpu):
                    self.assertEqual([cpu.low(r) for r in (4, 5, 6)], [1, 19, 23])
                m.handlers = {"cb_keep": check, "orig_unlink": unlink, "orig_unload": unload}
                m.run(stop=self.c.g + nxt)
                if keep:
                    self.assertEqual(m.events, ["cb_keep"])
                    m.compare(self, m.before)
                else:
                    self.assertEqual(m.events, ["cb_keep", "orig_unlink", "orig_unload"])
                    self.assertEqual(m.reg[16], record)
                    self.assertEqual(m.reg[29], m.before[0][29])

    def test_fallback_tail_chains_maintenance_once(self):
        args = tuple(range(10, 18))
        m = Machine(self.c, self.linked, "hook_fallback", args)

        def maintenance(cpu):
            cpu.compare(self, m.before)
        m.handlers["orig_maintenance"] = maintenance
        m.run()
        self.assertEqual(m.events, ["cb_fallback", "orig_maintenance"])
        m.compare(self, m.native_post)


class GuardTests(unittest.TestCase):
    def test_config_fail_closed(self):
        c = config()
        for name in h.CALLBACKS:
            for bad in (0, 3, 0x2000000, 0x1700000):
                with self.assertRaises(ValueError):
                    replace(c, callbacks={**c.callbacks, name: bad})
        for changes in ({"context_size": 0}, {"context": c.code}, {"g": 3},
                        {"callback_gp": 3}, {"trusted_code": ()},
                        {"code_size": 33}, {"code_size": 0x20000},
                        {"originals": {**c.originals, "chip": c.g + 0x1EA90}}):
            with self.assertRaises(ValueError):
                replace(c, **changes)

    @unittest.skipUnless(ORIGINAL.exists() and AS.exists(), "private original/EE assembler unavailable")
    def test_source_guards_patches_delay_slots_and_state6(self):
        c = config()
        expected = h.guard_expectations(c)
        e = h.Evidence(ORIGINAL.read_bytes(), "private original XFF, read-only", expected)
        built = h.build(c, e, assembler=AS)
        patched = {p.address: p for p in built.patches}
        self.assertEqual(len(patched), 14)
        for site in h.CALLS.values():
            self.assertNotIn(c.g + site + 4, patched)
            self.assertEqual(patched[c.g + site].replacement >> 26, 3)
        for site in (0x21020,) + tuple(p for p, _ in h.EVICTIONS):
            self.assertEqual(patched[c.g + site].replacement >> 26, 2)
            self.assertEqual(patched[c.g + site + 4].replacement, 0)
        for site in (0x21248, 0x21438, 0x215E0):
            self.assertTrue(all(c.g + site + off not in patched for off in range(0, 24, 4)))
        for p in built.patches:
            self.assertEqual(p.expected, expected[p.address])
        for address in expected:
            changed = dict(expected)
            changed[address] ^= 1
            with self.assertRaises(ValueError):
                h.verify(c, replace(e, observed_words=changed))
        with self.assertRaises(ValueError):
            h.verify(c, replace(e, observed_words={}))
        with self.assertRaises(ValueError):
            h.verify(c, replace(e, provenance=""))
        with self.assertRaises(ValueError):
            h.verify(c, replace(e, original_xff=e.original_xff[:-1]))


if __name__ == "__main__":
    unittest.main()
