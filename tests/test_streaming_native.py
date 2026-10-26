"""Execute assembled adapter bytes against hostile synthetic native callees.

No emulator connection or target writes. Original-XFF tests are optional and
read-only; all instruction execution below uses synthetic RAM and callbacks.
"""

import struct
import unittest
from dataclasses import replace

from streaming import native as n
from local_config import ee_tool, original_file

AS = ee_tool("as")
ORIGINAL = original_file("GAMECORE.XFF")
MASK = (1 << 128) - 1


def config():
    return n.Config(
        g=0x300000, gp=0x141D70, code=0x1400000, width=37, height=23,
        trusted_code=((0x300038, 0x130000), (0x1A00000, 0x10000)),
    )


def prove_leaf(case, raw):
    """Check definite GPR/FPR assignment over all suffix branches/table targets.

    FP branches are nondeterministic and likely delay slots are conditional.
    This proves missing-prefix/SP/GP/FPR independence, not numeric semantics.
    """
    words = {off: struct.unpack_from("<I", raw, off - 0x38)[0]
             for off in range(n.POLICY, 0x1F560, 4)}
    entry = frozenset((0, 6, 7, 8, 9, 10, 11, 13, 14, 31))
    seen, pending = {}, [(n.POLICY, entry)]

    def access(word, defined):
        op, rs, rt = word >> 26, word >> 21 & 31, word >> 16 & 31
        rd, fn = word >> 11 & 31, word & 63
        reads, writes = set(), set()
        if op == 0:
            if fn == 0:
                reads.add(rt)
                writes.add(rd)
            elif fn == 8:
                reads.add(rs)
            elif fn in (24, 33, 35, 42, 45):
                reads.update((rs, rt))
                writes.add(rd)
            else:
                case.fail(f"unexpected suffix SPECIAL {word:08x}")
        elif op == 15:
            writes.add(rt)
        elif op in (9, 11, 35):
            reads.add(rs)
            writes.add(rt)
        elif op == 49:
            reads.add(rs)
            case.assertLess(rt, 4)
            writes.add(32 + rt)
        elif op in (4, 5, 20, 21):
            reads.update((rs, rt))
        elif op == 1:
            reads.add(rs)
        elif op == 17:
            case.assertIn(rs, (4, 8, 16, 20))
            fs, fd = word >> 11 & 31, word >> 6 & 31
            if rs == 4:
                reads.add(rt)
                case.assertLess(fs, 4)
                writes.add(32 + fs)
            elif rs == 8:
                reads.add(64)  # FP comparison condition
            else:
                case.assertLess(fs, 4)
                reads.add(32 + fs)
                if rs == 16 and fn in (0, 52, 54):
                    case.assertLess(rt, 4)
                    reads.add(32 + rt)
                if fn in (52, 54):
                    writes.add(64)
                else:
                    case.assertIn((rs, fn), ((16, 0), (16, 7), (20, 32)))
                    case.assertLess(fd, 4)
                    writes.add(32 + fd)
        else:
            case.fail(f"unexpected suffix opcode {op}")
        case.assertFalse((reads | writes) & (set(range(16, 24)) | {28, 29, 30}))
        case.assertTrue(reads <= defined, (hex(word), reads - defined))
        return defined | writes

    while pending:
        pc, defined = pending.pop()
        case.assertIn(pc, words)
        if pc in seen:
            merged = seen[pc] & defined
            if merged == seen[pc]:
                continue
            defined = merged
        seen[pc] = defined
        word = words[pc]
        after = access(word, defined)
        op, rs, rt, fn = word >> 26, word >> 21 & 31, word >> 16 & 31, word & 63
        if op == 0 and fn == 8:
            after = access(words[pc + 4], after)
            if rs == 31:
                continue
            case.assertEqual(rs, 3)
            pending.extend((dest, after) for dest in n.TABLE_TARGETS)
        elif op in (1, 4, 5, 20, 21) or (op == 17 and rs == 8):
            imm = (word & 65535) - (65536 if word & 32768 else 0)
            delay = access(words[pc + 4], after)
            likely = op in (20, 21) or (op == 1 and rt in (2, 3)) or (op == 17 and rt & 2)
            pending.append((pc + 4 + imm * 4, delay))
            if not (op == 4 and rs == rt):
                pending.append((pc + 8, after if likely else delay))
        else:
            pending.append((pc + 4, after))


class Machine:
    """Small decoder for the actual EE instructions emitted by these adapters."""

    def __init__(self, c, linked, symbol, args):
        self.c, self.mem, self.events = c, {}, []
        self.reg = [0] + [((0x12340000 + i) << 96) | (0x200000 + i) for i in range(1, 32)]
        self.reg[29] = (0xAABBCCDD << 96) | 0x1F00000
        self.reg[31] = (0xDEADBEEF << 96) | 0x1FFFF00
        for i, value in enumerate(args):
            self.reg[4 + i] = value
        self.original = self.reg.copy()
        self.hi, self.lo = 0, 0
        self.start_sp = self.low(29)
        for off in range(64):
            self.mem[self.start_sp + off] = 0xA7
        for p in linked.payloads:
            self.write(p.address, p.data)
        self.pc = linked.exports[symbol]
        self.callback = None
        self.policy_result = 1

    def low(self, reg):
        return self.reg[reg] & 0xFFFFFFFF

    def set(self, reg, value):
        if reg:
            self.reg[reg] = value & MASK

    def write(self, addr, data):
        assert 0 <= addr <= n.EE_SIZE - len(data)
        for i, byte in enumerate(data):
            self.mem[addr + i] = byte

    def read(self, addr, count):
        assert 0 <= addr <= n.EE_SIZE - count
        return bytes(self.mem.get(addr + i, 0) for i in range(count))

    def word(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def external(self):
        target = self.pc
        assert target in (self.c.g + n.POLICY, self.c.g + n.BATCH)
        self.events.append(target)
        ret = self.low(31)
        assert self.low(28) == self.c.gp
        if self.callback:
            self.callback(self)
        # Real native callees may use every outgoing home and preserve only
        # the lower ABI lanes of saved registers. Deliberately destroy more
        # than the suffix does, so the wrapper's full-width saves are tested.
        self.write(self.low(29), bytes([0xCC]) * 64)
        for r in range(1, 32):
            if r == 29:
                continue
            if r in tuple(range(16, 24)) + (28, 30):
                self.reg[r] = (0xBADBEEF << 96) | (self.reg[r] & ((1 << 64) - 1))
            else:
                self.reg[r] = (0xABCD << 96) | (0x554400 + r)
        self.hi, self.lo = 123, 456
        self.reg[2] = 0x55667788 if target == self.c.g + n.BATCH else self.policy_result
        self.pc = ret

    def execute(self, pc):
        word = self.word(pc)
        op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        rd, sa, fn = (word >> 11) & 31, (word >> 6) & 31, word & 63
        imm = word & 65535
        signed = imm - (65536 if imm & 32768 else 0)
        a, b = self.low(rs), self.low(rt)
        if word == 0:
            pass
        elif op == 0:
            if fn == 0:
                self.set(rd, b << sa)
            elif fn == 8:
                return a
            elif fn == 9:
                self.set(rd, pc + 8)
                return a
            elif fn == 0x19:
                product = a * b
                self.hi, self.lo = product >> 32, product & 0xFFFFFFFF
            elif fn == 0x10:
                self.set(rd, self.hi)
            elif fn == 0x12:
                self.set(rd, self.lo)
            elif fn == 0x21:
                self.set(rd, (a + b) & 0xFFFFFFFF)
            elif fn == 0x25:
                self.set(rd, self.reg[rs] | self.reg[rt])
            elif fn == 0x2B:
                self.set(rd, int(a < b))
            else:
                raise AssertionError(f"unsupported SPECIAL {word:08x}")
        elif op == 0x1C and fn == 0x29 and sa == 0x12:  # POR MMI3
            self.set(rd, self.reg[rs] | self.reg[rt])
        elif op in (4, 5):
            take = (a == b) if op == 4 else (a != b)
            return pc + 4 + signed * 4 if take else pc + 8
        elif op == 9:
            self.set(rt, (a + signed) & 0xFFFFFFFF)
        elif op == 0xB:
            self.set(rt, int(a < (signed & 0xFFFFFFFF)))
        elif op == 0xC:
            self.set(rt, a & imm)
        elif op == 0xD:
            self.set(rt, a | imm)
        elif op == 0xF:
            self.set(rt, imm << 16)
        elif op in (0x23, 0x2B, 0x1E, 0x1F):
            address = (a + signed) & 0xFFFFFFFF
            size = 16 if op in (0x1E, 0x1F) else 4
            assert address % size == 0
            if op in (0x23, 0x1E):
                self.set(rt, int.from_bytes(self.read(address, size), "little"))
            else:
                self.write(address, (self.reg[rt] & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
        else:
            raise AssertionError(f"unsupported instruction {word:08x} at {pc:x}")
        return None

    def run(self):
        for _ in range(20000):
            if self.pc == self.original[31] & 0xFFFFFFFF:
                return
            if self.pc in (self.c.g + n.POLICY, self.c.g + n.BATCH):
                self.external()
                continue
            target = self.execute(self.pc)
            if target is None:
                self.pc += 4
            else:
                assert self.execute(self.pc + 4) is None
                self.pc = target
        raise AssertionError("adapter did not return")

    def preserved(self, case):
        for reg in tuple(range(16, 24)) + (28, 29, 30, 31):
            case.assertEqual(self.reg[reg], self.original[reg], f"register {reg}")
        case.assertEqual(self.read(self.start_sp, 64), bytes([0xA7]) * 64)


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not AS.exists():
            raise unittest.SkipTest("real EE assembler not available")
        cls.c = config()
        # Synthetic target substitutes; no unverified payload is installed.
        cls.linked = n._assemble(cls.c, n.render(cls.c), AS)

    def test_policy_seven_arguments_and_index(self):
        args = (17, 11, 1, 18, 12, 17, 11)
        m = Machine(self.c, self.linked, "stream_policy", args)

        def inspect(cpu):
            self.assertEqual([cpu.low(r) for r in (13, 14, 11, 6, 7, 8, 9, 10)],
                             [17, 11, 17 + 11 * 37, 1, 18, 12, 17, 11])
        m.callback = inspect
        m.run()
        self.assertEqual(m.events, [self.c.g + n.POLICY])
        self.assertEqual(m.low(2), 1)
        m.preserved(self)
        # Rounded coordinates at the map edge are legal; containing are not.
        m = Machine(self.c, self.linked, "stream_policy", (36, 22, 0, 37, 23, 36, 22))
        m.run()
        self.assertEqual(len(m.events), 1)
        m = Machine(self.c, self.linked, "stream_policy", args)
        m.policy_result = 0
        m.run()
        self.assertEqual(m.events, [self.c.g + n.POLICY])
        self.assertEqual(m.low(2), 0)
        m.preserved(self)

    def test_policy_invalid_never_calls(self):
        base = [17, 11, 1, 18, 12, 17, 11]
        for slot, value in ((0, 37), (0, 0xFFFFFFFF), (1, 23), (2, 2),
                            (3, 38), (4, 24), (5, 37), (6, 23)):
            args = base.copy()
            args[slot] = value
            m = Machine(self.c, self.linked, "stream_policy", args)
            m.run()
            self.assertEqual(m.events, [])
            self.assertEqual(m.low(2), 0)
            m.preserved(self)

    def batch_machine(self, words=None, points=None, pointer=0x1800000):
        words = words or [0x1700000, 3, 2, 3, 5, 4, 5, 5, 4, 4]
        points = points or [(2, 3), (6, 6), (4, 4)]
        m = Machine(self.c, self.linked, "stream_batch", [pointer])
        if pointer and pointer <= n.EE_SIZE - 40 and pointer % 4 == 0:
            m.write(pointer, struct.pack("<10I", *words))
        if words[0] and words[0] <= n.EE_SIZE - len(points) * 16:
            for i, (x, z) in enumerate(points):
                m.write(words[0] + i * 16, struct.pack("<4I", x, z, 0x11111111, 0x22222222))
        return m, words

    def test_batch_ten_arguments_and_home_clobber(self):
        m, words = self.batch_machine()

        def inspect(cpu):
            self.assertEqual([cpu.low(r) for r in range(4, 12)], words[:8])
            self.assertEqual(cpu.word(cpu.low(29)), words[8])
            self.assertEqual(cpu.word(cpu.low(29) + 8), words[9])
            self.assertEqual(cpu.low(29), cpu.start_sp - 256)
        m.callback = inspect
        m.run()
        self.assertEqual(m.events, [self.c.g + n.BATCH])
        self.assertEqual(m.low(2), 1)  # Not the native void callee's v0 garbage.
        m.preserved(self)

    def test_batch_rejections(self):
        base = [0x1700000, 3, 2, 3, 5, 4, 5, 5, 4, 4]
        bad = ((0, 0), (0, 0x1700004), (0, n.EE_SIZE - 16),
               (1, 0), (1, 257), (1, 21), (4, 0), (4, 17), (5, 17),
               (2, 37), (3, 23), (2, 35), (3, 22), (6, 38), (7, 24),
               (8, 37), (9, 23), (2, 0xFFFFFFFF))
        for slot, value in bad:
            words = base.copy()
            words[slot] = value
            m, _ = self.batch_machine(words)
            m.run()
            self.assertEqual(m.events, [], (slot, value))
            self.assertEqual(m.low(2), 0)
            m.preserved(self)
        for point in ((1, 3), (7, 3), (2, 2), (2, 7), (0xFFFFFFFF, 3)):
            m, _ = self.batch_machine(points=[(2, 3), (6, 6), point])
            m.run()
            self.assertEqual(m.events, [])
            m.preserved(self)
        for pointer in (0, 3, n.EE_SIZE - 36):
            m, _ = self.batch_machine(pointer=pointer)
            m.run()
            self.assertEqual(m.events, [])
            m.preserved(self)

    def test_maximum_tile(self):
        words = [0x1700000, 256, 0, 0, 16, 16, 10, 10, 10, 10]
        points = [(x, z) for z in range(16) for x in range(16)]
        m, _ = self.batch_machine(words, points)
        m.run()
        self.assertEqual(m.events, [self.c.g + n.BATCH])
        m.preserved(self)


class BindingTests(unittest.TestCase):
    def test_reject_bad_config(self):
        c = config()
        for changes in ({"width": 0}, {"width": 4097}, {"height": 4096},
                        {"gp": 3}, {"code": c.g + 0x20000}, {"trusted_code": ()},
                        {"width": True}, {"g": 0x1FFFFFC}):
            with self.assertRaises(ValueError):
                replace(c, **changes)

    @unittest.skipUnless(ORIGINAL.exists(), "private original XFF unavailable")
    def test_original_metadata_guards_and_radius_evidence(self):
        c = config()
        original = ORIGINAL.read_bytes()
        module = n.parse(original)
        prove_leaf(self, module.sections[module.index_of(".text")].data)
        bases, imports, cursor = {".text": c.g + 0x38}, {}, 0x800000
        for section in module.sections:
            if section.name and section.name != ".text":
                bases[section.name] = cursor
                cursor = (cursor + max(section.size, 16) + 15) & ~15
        for index in range(module.num_symbols):
            if module.symbol(index)[5] == 0:
                imports[module.symbol_name(index)] = 0x1A00000 + index * 4 % 0x10000
        e = n.Evidence(original, "private original GAMECORE.XFF; read-only fixture",
                       bases, imports, {})
        expected = n.expected_guards(c, e)
        self.assertEqual(expected[c.g + n.POLICY] >> 26, 15)  # LUI t7
        self.assertEqual(expected[c.g + 0x1EF58], 0x0080682D)  # t5=x
        self.assertEqual(expected[c.g + 0x1F19C], 0x468018E0)  # cvt.s.w f3,f3
        self.assertEqual(expected[c.g + 0x22018] >> 26, 0x23)  # integer lw
        self.assertEqual(expected[c.g + 0x22034] >> 26, 0x2B)  # integer sw
        self.assertEqual(expected[c.g + 0x20DB4], 0xAFB60000)
        self.assertEqual(expected[c.g + 0x20DBC], 0xAFB50008)
        self.assertEqual((expected[c.g + 0x200F0] & 0x3FFFFFF) << 2,
                         c.g + 0x1EF58)
        self.assertEqual((expected[c.g + 0x20DB8] & 0x3FFFFFF) << 2,
                         c.g + n.BATCH)
        n.verify(c, replace(e, observed_words=expected))
        for address in (c.g + n.POLICY, c.g + 0x1F558, c.g + n.BATCH,
                        c.g + 0x20DB4, min(a for a in expected if a >= 0x800000)):
            changed = dict(expected)
            changed[address] ^= 1
            with self.assertRaises(ValueError):
                n.verify(c, replace(e, observed_words=changed))
        with self.assertRaises(ValueError):
            n.verify(c, e)
        with self.assertRaises(ValueError):
            n.expected_guards(c, replace(e, provenance=""))
        with self.assertRaises(ValueError):
            n.expected_guards(c, replace(e, section_bases={**bases, ".text": c.g}))
        altered = bytearray(original)
        altered[-1] ^= 1
        with self.assertRaises(ValueError):
            n.expected_guards(c, replace(e, original_xff=bytes(altered)))
        with self.assertRaises(ValueError):
            n.expected_guards(replace(c, trusted_code=(c.trusted_code[0],)), e)
        if AS.exists():
            built = n.build(c, replace(e, observed_words=expected), assembler=AS)
            self.assertEqual(set(built.linked.exports), {"stream_policy", "stream_batch"})


if __name__ == "__main__":
    unittest.main()
