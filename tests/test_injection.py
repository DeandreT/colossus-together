"""Synthetic EE instruction execution: never loads any game binary."""

import re
import struct
import unittest
from dataclasses import replace

from injection.adapter import (
    AllocationIdentityMap,
    ConstructorMetadata,
    ControllerAdapter,
    DeleteMetadata,
    VerifiedAllocationIdentity,
    map_record,
)
from injection.generator import (
    FREE_CALL_OFFSET,
    Config,
    guard_expectations,
    render,
    validate_prologues,
)
from injection.records import (
    ALLOCATION_INVALID,
    CAPACITY,
    GP_INVALID,
    PARAM_MISSING,
    RING_SIZE,
    STRIDE,
    Kind,
    RingReader,
    TelemetryLoss,
    decode_record,
    initial_state,
)
from lifecycle import (
    CanonicalFinalFree,
    CanonicalRegistered,
    GameplayReady,
    Lifecycle,
    OwnedFinalFree,
    Part,
)

CONFIG = Config(0x100000, 0x500000, 0x900000, 0x1400000, 0x1500000, 0x1510000)
WORDS = {address: word for address, (word, _) in guard_expectations(CONFIG).items()}


class Memory:
    def __init__(self):
        self.data = {}
        self.put(CONFIG.state, initial_state())
        self.put(CONFIG.ring, bytes(RING_SIZE))
        self.put(0x200000, bytes(range(60)))
        self.put(0x200020, struct.pack("<I", 0x300001))
        self.put(0x300001, bytes(range(64)))
        self.put(0x444440, struct.pack("<I", 0x440000))
        self.writes = []
        self.reads = []
        self.forbidden = set()

    def put(self, address, data):
        for i, value in enumerate(data):
            self.data[address + i] = value

    def read(self, address, size):
        assert not any(
            byte in self.forbidden for byte in range(address, address + size)
        ), "freed memory read"
        self.reads.append((address, size))
        return bytes(self.data[address + i] for i in range(size))

    def write(self, address, value, size):
        assert (
            CONFIG.ring <= address < address + size <= CONFIG.ring + RING_SIZE
            or CONFIG.state <= address < address + size <= CONFIG.state + 32
        )
        if size == 16:
            assert address % 16 == 0
        self.writes.append((address, size))
        self.put(address, (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little"))

    def snapshot(self):
        return self.read(CONFIG.state, 32), self.read(CONFIG.ring, RING_SIZE)


class Machine:
    """Interpret the renderer's small instruction subset, including delay slots.

    Original routines are callbacks, not game code. Assertions guard the exact
    entry ABI; callbacks simulate callee-save restoration and volatile clobbers.
    """

    def __init__(self, memory=None, config=CONFIG):
        self.memory = memory or Memory()
        self.regs = {
            name: 0
            for name in (
                "zero",
                "s0",
                "s1",
                "ra",
                "sp",
                "v0",
                "v1",
                "a0",
                "a1",
                "a2",
                "a3",
                *[f"t{i}" for i in range(10)],
            )
        }
        self.regs.update(
            s0=(1 << 120) | 0x11223344, ra=(1 << 100) | 0xDEAD, sp=0x1F00000
        )
        for index, name in enumerate(("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3")):
            self.regs[name] = (1 << 96) | 0x400000 + index * 16
        self.regs["a2"] = 0x200000
        self.instructions, self.labels = [], {}
        words = {a: v for a, (v, _) in guard_expectations(config).items()}
        for line in render(config, words).splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.instructions)
            elif not line.startswith("."):
                self.instructions.append(line)
        self.calls = 0
        self.return_value = (1 << 110) | 0x444440

    def run(self, kind="script_char", callback=None):
        r, m = self.regs, self.memory
        saved = {
            name: r[name]
            for name in (
                "s0",
                "s1",
                "ra",
                "sp",
                "a0",
                "a1",
                "a2",
                "a3",
                "t0",
                "t1",
                "t2",
                "t3",
            )
        }
        pc = self.labels[f"hook_{kind}"]
        tramp = self.labels[f"trampoline_{kind}"]
        for _ in range(5000):
            if pc == tramp:
                self.calls += 1
                for name in ("sp", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"):
                    assert r[name] == saved[name], name
                assert r["s1"] == saved["s1"]
                if callback:
                    callback(self)
                for i in range(10):
                    r[f"t{i}"] = 0xDEADBEEF
                r["v0"], r["v1"] = self.return_value, 0xFAFA
                if r["ra"] == saved["ra"]:  # overflow/delete tail call
                    return
                pc = r["ra"]
                r["s0"] &= (1 << 64) - 1  # actual game's sd/ld pair
                continue
            line = self.instructions[pc]
            op, *args = re.split(r"[ ,]+", line)

            def reg(token):
                return r[token.removeprefix("$")]

            def setreg(token, value):
                r[token.removeprefix("$")] = value

            def number(token):
                return int(token, 0)

            if op in ("b", "beq", "bne", "jal", "jr"):
                assert self.instructions[pc + 1] == "nop", line
                target = None
                if op in ("b", "jal"):
                    target = self.labels[args[0]]
                elif op == "jr":
                    assert reg(args[0]) == saved["ra"]
                    assert r["s0"] == saved["s0"]
                    assert r["s1"] == saved["s1"]
                    assert r["v0"] == self.return_value
                    assert r["v1"] == 0xFAFA
                    return
                elif (reg(args[0]) == reg(args[1])) == (op == "beq"):
                    target = self.labels[args[2]]
                if op == "jal":
                    r["ra"] = pc + 2
                pc = pc + 2 if target is None else target
                continue
            if op == "lui":
                setreg(args[0], number(args[1]) << 16)
            elif op in ("addu", "subu", "daddu", "or", "sltu"):
                a, b = reg(args[1]), reg(args[2])
                value = {
                    "addu": lambda a, b: (a + b) & 0xFFFFFFFF,
                    "subu": lambda a, b: (a - b) & 0xFFFFFFFF,
                    "daddu": lambda a, b: (a + b) & ((1 << 64) - 1),
                    "or": lambda a, b: a | b,
                    "sltu": lambda a, b: int(
                        (a & ((1 << 64) - 1)) < (b & ((1 << 64) - 1))
                    ),
                }[op](a, b)
                setreg(args[0], value)
            elif op in ("ori", "andi", "addiu", "sll", "sltiu"):
                a, b = reg(args[1]), number(args[2])
                value = {
                    "ori": lambda a, b: a | b,
                    "andi": lambda a, b: a & b,
                    "addiu": lambda a, b: (a + b) & 0xFFFFFFFF,
                    "sll": lambda a, b: (a << b) & 0xFFFFFFFF,
                    "sltiu": lambda a, b: int((a & ((1 << 64) - 1)) < b),
                }[op](a, b)
                setreg(args[0], value)
            elif op in ("lw", "sw", "lbu", "sb", "lq", "sq"):
                match = re.fullmatch(r"(\d+)\((\$\w+)\)", args[1])
                address = number(match[1]) + (reg(match[2]) & 0xFFFFFFFF)
                size = {"lw": 4, "sw": 4, "lbu": 1, "sb": 1, "lq": 16, "sq": 16}[op]
                if op.startswith("l"):
                    setreg(args[0], int.from_bytes(m.read(address, size), "little"))
                else:
                    m.write(address, reg(args[0]), size)
            elif op not in ("nop", "sync"):
                raise AssertionError(line)
            pc += 1
        raise AssertionError("instruction bound exceeded")


class InjectionTests(unittest.TestCase):
    def test_final_free_watch_filters_without_changing_original_call(self):
        watch = 0x1700000
        config = replace(CONFIG, free_watch=watch, free_watch_capacity=2)
        for count, allocation, expected in (
            (0, 0x400000, 0),
            (1, 0x400004, 0),
            (1, 0x400000, 1),
        ):
            with self.subTest(count=count, allocation=allocation):
                machine = Machine(config=config)
                machine.regs["a0"] = allocation
                machine.memory.put(watch, struct.pack("<3I", count, 0x400000, 0))
                machine.run("final_free_allocation")
                self.assertEqual(machine.calls, 1)
                state, ring = machine.memory.snapshot()
                self.assertEqual(struct.unpack_from("<I", state, 16)[0], expected)
                if expected:
                    self.assertEqual(
                        decode_record(ring[:STRIDE], 1).kind, Kind.FINAL_FREE_ALLOCATION
                    )

    def test_invalid_watch_count_latches_capture_loss_not_table_data(self):
        watch = 0x1700000
        config = replace(CONFIG, free_watch=watch, free_watch_capacity=2)
        machine = Machine(config=config)
        machine.memory.put(watch, struct.pack("<3I", 3, 0x400000, 0))
        machine.run("final_free_allocation")
        self.assertEqual(machine.calls, 1)
        self.assertEqual(
            struct.unpack_from("<I", machine.memory.snapshot()[0], 24)[0], 1
        )
        self.assertEqual(
            machine.memory.read(watch, 12), struct.pack("<3I", 3, 0x400000, 0)
        )

    def test_prologue_guards_and_config(self):
        validate_prologues(CONFIG, WORDS)
        for address in WORDS:
            bad = dict(WORDS)
            mask = guard_expectations(CONFIG)[address][1]
            bad[address] ^= mask & -mask
            with self.assertRaises(ValueError):
                render(CONFIG, bad)
            del bad[address]
            with self.assertRaises(ValueError):
                validate_prologues(CONFIG, bad)
        with self.assertRaises(ValueError):
            Config(0x100000, 0x500000, 0x900000, CONFIG.ring, CONFIG.ring, CONFIG.state)

    def test_capture_abi_bytes_and_adapter(self):
        for kind in ("script_char", "alias_layout"):
            machine = Machine()
            machine.run(kind)
            records, cursor = RingReader().drain(*machine.memory.snapshot())
            self.assertEqual(cursor, 1)
            record = records[0]
            self.assertEqual(record.object_ptr, machine.return_value & 0xFFFFFFFF)
            self.assertEqual(record.allocation_ptr, 0x440000)
            self.assertEqual(record.parameters, machine.memory.read(0x200000, 60))
            self.assertEqual(record.gp_bytes, bytes(range(64)))
            self.assertEqual(
                record.alias_source, 0x400040 if kind == "alias_layout" else None
            )
            self.assertTrue(map_record(record).missing)
            metadata = ConstructorMetadata(
                1,
                2,
                Part.BODY,
                0x1234,
                frozenset({"resource"}),
                0x600000,
                bytes(range(64)),
            )
            event = map_record(record, metadata).event
            self.assertEqual(event.record.gp_copy, 0x600000)
            self.assertEqual(event.record.parameter_copy, record.parameters)

    def test_nested_completion_waits_for_outer(self):
        outer = Machine()

        def during(machine):
            Machine(machine.memory).run("alias_layout")
            records, cursor = RingReader().drain(*machine.memory.snapshot())
            self.assertEqual((records, cursor), ((), 0))

        outer.run(callback=during)
        records, cursor = RingReader().drain(*outer.memory.snapshot())
        self.assertEqual(
            [record.kind for record in records], [Kind.SCRIPT_CHAR, Kind.ALIAS_LAYOUT]
        )
        self.assertEqual(cursor, 2)

    def test_snapshot_precedes_original_mutation(self):
        machine = Machine()
        parameters = machine.memory.read(0x200000, 60)

        def mutate(original):
            original.memory.put(0x200000, bytes(60))
            original.memory.put(0x300001, bytes(64))

        machine.run(callback=mutate)
        record = RingReader().drain(*machine.memory.snapshot())[0][0]
        self.assertEqual(record.parameters, parameters)
        self.assertEqual(record.gp_bytes, bytes(range(64)))

    def test_overflow_inside_nested_calls_preserves_reserved_slots(self):
        memory = Memory()
        count = 0

        def descend(_):
            nonlocal count
            count += 1
            if count <= CAPACITY:
                Machine(memory).run(callback=descend)

        Machine(memory).run(callback=descend)
        self.assertEqual(count, CAPACITY + 1)
        self.assertEqual(memory.read(CONFIG.state + 24, 4), b"\1\0\0\0")
        for slot in range(CAPACITY):
            data = memory.read(CONFIG.ring + slot * STRIDE, STRIDE)
            self.assertEqual(decode_record(data, slot + 1).object_ptr, 0x444440)

    def test_delete_published_before_original(self):
        machine = Machine()

        def during(machine):
            records, _ = RingReader().drain(*machine.memory.snapshot())
            self.assertEqual(records[0].object_ptr, 0x400000)
            self.assertIsNone(map_record(records[0], DeleteMetadata(1, 0xBAD)).event)
            self.assertIsNotNone(
                map_record(records[0], DeleteMetadata(1, 0x400000)).event
            )
            self.assertIsNotNone(
                map_record(records[0], DeleteMetadata(ownership_id=9)).event
            )

        machine.run("delete_request", during)

    @staticmethod
    def prepare_free_callsite(machine):
        # Execute the verified caller instructions, including the JAL delay:
        # lw a0,0(s1); jal hook; daddu s1,s0,zero.
        machine.regs["s1"] = 0x444440
        machine.regs["s0"] = 0x777700
        machine.regs["a0"] = int.from_bytes(
            machine.memory.read(machine.regs["s1"], 4), "little"
        )
        machine.regs["ra"] = CONFIG.k + FREE_CALL_OFFSET + 8
        machine.regs["s1"] = machine.regs["s0"]

    def test_final_free_after_return_uses_saved_allocation_not_next_s1(self):
        memory = Memory()
        Machine(memory).run()
        constructor = RingReader().drain(*memory.snapshot())[0][0]
        identities = AllocationIdentityMap()
        identity = VerifiedAllocationIdentity(0x440000, 0x444440, 7, 1, ownership_id=17)
        identities.register(constructor, identity)
        machine = Machine(memory)
        self.prepare_free_callsite(machine)

        def free(original):
            self.assertEqual(original.regs["a0"], constructor.allocation_ptr)
            self.assertEqual(original.regs["s1"], 0x777700)
            records, cursor = RingReader().drain(*memory.snapshot())
            self.assertEqual((len(records), cursor), (1, 1))
            self.assertEqual(records[0].kind, Kind.SCRIPT_CHAR)
            # Every allocation/object byte becomes unreadable before return.
            memory.forbidden.update(range(0x440000, 0x444444))
            original.regs["a0"] = 0xDEADBEEF

        machine.run("final_free_allocation", free)
        self.assertEqual(machine.regs["s1"], 0x777700)
        self.assertEqual(machine.regs["ra"], CONFIG.k + FREE_CALL_OFFSET + 8)
        records, _ = RingReader().drain(*memory.snapshot())
        final_free = records[1]
        self.assertEqual(final_free.kind, Kind.FINAL_FREE_ALLOCATION)
        self.assertEqual(final_free.allocation_ptr, 0x440000)
        self.assertEqual(final_free.object_ptr, 0)
        unknown = map_record(final_free)
        self.assertIsNone(unknown.event)
        self.assertEqual(unknown.raw, final_free)
        self.assertEqual(
            map_record(final_free, identities.resolve(final_free)).event,
            OwnedFinalFree(17),
        )
        canonical = VerifiedAllocationIdentity(0x440000, 0x444440, 7, 1, canonical=True)
        self.assertEqual(
            map_record(final_free, canonical).event, CanonicalFinalFree(7, 0x444440)
        )
        wrong = VerifiedAllocationIdentity(0x450000, 0x444440, 7, 1, ownership_id=17)
        self.assertIsNone(map_record(final_free, wrong).event)
        identities.retire(final_free)
        self.assertIsNone(identities.resolve(final_free))
        with self.assertRaises(ValueError):
            identities.retire(final_free)

    def test_final_free_nonlocal_failure_never_commits(self):
        machine = Machine()
        self.prepare_free_callsite(machine)

        class NonlocalExit(Exception):
            pass

        def fail(_):
            raise NonlocalExit

        with self.assertRaises(NonlocalExit):
            machine.run("final_free_allocation", fail)
        records, cursor = RingReader().drain(*machine.memory.snapshot())
        self.assertEqual((records, cursor), ((), 0))
        self.assertEqual(machine.calls, 1)

    def test_created_allocation_read_requires_aligned_ram_object(self):
        for object_ptr in (0, 0x7FFFF, 0x444441, 0x2000000, 0xFFFFFFFF):
            machine = Machine()
            machine.return_value = object_ptr
            machine.run()
            record = RingReader().drain(*machine.memory.snapshot())[0][0]
            self.assertEqual(record.allocation_ptr, 0)
            self.assertEqual(record.flags, ALLOCATION_INVALID if object_ptr else 0)
        machine = Machine()
        machine.return_value = 0x1FFFFFC
        machine.memory.put(0x1FFFFFC, struct.pack("<I", 0x440000))
        machine.run()
        self.assertEqual(
            RingReader().drain(*machine.memory.snapshot())[0][0].allocation_ptr,
            0x440000,
        )

    def test_allocation_map_rejects_unverified_reuse_and_stale_final_free(self):
        from dataclasses import replace

        machine = Machine()
        machine.run()
        constructor = RingReader().drain(*machine.memory.snapshot())[0][0]
        identities = AllocationIdentityMap()
        identity = VerifiedAllocationIdentity(0x440000, 0x444440, 7, 1, ownership_id=17)
        identities.register(constructor, identity)
        with self.assertRaises(ValueError):
            identities.register(constructor, replace(identity, object_ptr=0x555550))
        with self.assertRaises(ValueError):
            identities.register(
                replace(constructor, sequence=3),
                replace(identity, generation=8, constructor_sequence=3),
            )
        raw = replace(constructor, kind=Kind.FINAL_FREE_ALLOCATION, object_ptr=0)
        self.assertIsNone(identities.resolve(raw))
        self.assertIsNone(map_record(raw, identity).event)

    def test_overflow_bypasses_and_loss_is_sticky(self):
        memory = Memory()
        for _ in range(CAPACITY):
            Machine(memory).run()
        before = memory.read(CONFIG.ring, RING_SIZE)
        overflow = Machine(memory)
        overflow.run()
        self.assertEqual(overflow.calls, 1)
        self.assertEqual(memory.read(CONFIG.ring, RING_SIZE), before)
        reader = RingReader()
        with self.assertRaises(TelemetryLoss):
            reader.drain(*memory.snapshot())
        with self.assertRaises(TelemetryLoss):
            reader.drain(initial_state(), bytes(RING_SIZE))
        lifecycle = Lifecycle()
        lifecycle.dispatch(CanonicalRegistered(1, 2, 0x500))
        controller = ControllerAdapter(lifecycle)
        with self.assertRaises(TelemetryLoss):
            controller.snapshot(*memory.snapshot(), lambda _: None)
        with self.assertRaises(TelemetryLoss):
            controller.dispatch(GameplayReady(1, True))

    def test_pointer_bounds_missing_gp_and_unaligned(self):
        for pointer in (0, 0x7FFFF, 0x2000000 - 59, 0xFFFFFFFF):
            machine = Machine()
            machine.regs["a2"] = pointer
            machine.run()
            record = RingReader().drain(*machine.memory.snapshot())[0][0]
            self.assertEqual(record.flags, PARAM_MISSING)
            self.assertEqual(record.parameters, b"")
        for pointer, flag in (
            (0, 0),
            (0x7FFFF, GP_INVALID),
            (0x2000000 - 63, GP_INVALID),
        ):
            machine = Machine()
            machine.memory.put(0x200020, struct.pack("<I", pointer))
            machine.run()
            record = RingReader().drain(*machine.memory.snapshot())[0][0]
            self.assertEqual(record.flags, flag)
            self.assertEqual(record.gp_bytes, b"")

    def test_reuse_and_acknowledgement(self):
        memory, reader = Memory(), RingReader()
        for sequence in range(1, 140):
            Machine(memory).run()
            records, cursor = reader.drain(*memory.snapshot())
            self.assertEqual(records[0].sequence, sequence)
            reader.acknowledge(cursor)
            memory.put(CONFIG.state + 20, struct.pack("<I", cursor))
        with self.assertRaises(TelemetryLoss):
            reader.acknowledge(1000)

    def test_bad_formats_and_sequence_exhaustion(self):
        machine = Machine()
        machine.run()
        data = bytearray(machine.memory.read(CONFIG.ring, STRIDE))
        for offset, value in ((0, 2), (8, 99), (12, 128), (24, 61), (28, 65)):
            corrupt = bytearray(data)
            struct.pack_into("<I", corrupt, offset, value)
            with self.assertRaises(TelemetryLoss):
                decode_record(corrupt, 1)
        machine = Machine()
        machine.memory.put(
            CONFIG.state + 16, struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
        )
        machine.run()
        self.assertEqual(machine.memory.read(CONFIG.state + 24, 4), b"\1\0\0\0")
        self.assertEqual(machine.calls, 1)


if __name__ == "__main__":
    unittest.main()
