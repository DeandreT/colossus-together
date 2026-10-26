import struct
import unittest
from dataclasses import FrozenInstanceError, replace

from injection.live_reader import LiveRingReader
from injection.records import CAPACITY, STRIDE, TelemetryLoss, initial_state

STATE, RING = 0x1000, 0x2000


class FakeMemory:
    def __init__(self):
        self.data = bytearray(RING + CAPACITY * STRIDE)
        self.data[STATE : STATE + 32] = initial_state()
        self.calls = []
        self.hook = lambda *_: None

    def word(self, address, value):
        struct.pack_into("<I", self.data, address, value)

    def publish(self, sequence, *, ready=True):
        address = RING + ((sequence - 1) % CAPACITY) * STRIDE
        self.data[address : address + STRIDE] = bytes(STRIDE)
        struct.pack_into(
            "<8I",
            self.data,
            address,
            sequence if ready else 0,
            sequence,
            3,
            0,
            0x80000,
            0,
            0,
            0,
        )
        self.word(address + 32, 0x80000)
        self.word(STATE + 16, sequence)

    def read_bulk(self, address, size):
        self.calls.append(("bulk", address, size))
        self.hook("bulk", address, size)
        return bytes(self.data[address : address + size])

    def read32(self, address):
        self.calls.append(("read", address))
        self.hook("read", address, 4)
        return struct.unpack_from("<I", self.data, address)[0]

    def write32(self, address, value):
        self.calls.append(("write", address, value))
        self.word(address, value)
        self.hook("write", address, value)


class LiveReaderTests(unittest.TestCase):
    def setUp(self):
        self.memory = FakeMemory()
        self.reader = LiveRingReader(self.memory, STATE, RING, "epoch-1")
        self.memory.calls.clear()

    def assert_no_writes(self):
        self.assertFalse(any(c[0] == "write" for c in self.memory.calls))

    def test_offer_and_explicit_ack(self):
        self.memory.publish(1)
        offer = self.reader.poll()
        self.assertEqual([r.sequence for r in offer.records], [1])
        self.assertEqual(offer.through_seq, 1)
        self.assertEqual(offer.epoch_identity.state_address, STATE)
        with self.assertRaises(FrozenInstanceError):
            offer.through_seq = 2
        with self.assertRaises(FrozenInstanceError):
            offer.records[0].flags = 1
        self.assert_no_writes()
        self.reader.acknowledge(offer)
        self.assertEqual(self.reader.consumer, 1)
        self.assertEqual(
            [c for c in self.memory.calls if c[0] == "write"],
            [("write", STATE + 20, 1)],
        )
        with self.assertRaises(TelemetryLoss):
            self.reader.acknowledge(offer)

    def test_producer_advances_without_invalidating_committed_snapshot(self):
        self.memory.publish(1)

        def advance(op, address, size):
            if op == "bulk" and address == RING:
                self.memory.publish(2)

        self.memory.hook = advance
        self.assertEqual(self.reader.poll().through_seq, 1)
        self.memory.hook = lambda *_: None
        self.assertEqual(self.reader.poll().through_seq, 2)
        self.assert_no_writes()

    def test_pending_outer_stops_before_blob_or_nested_record(self):
        self.memory.publish(1, ready=False)
        self.memory.publish(2)
        offer = self.reader.poll()
        self.assertEqual(offer.records, ())
        self.assertEqual(offer.through_seq, 0)
        self.assertEqual(
            [c for c in self.memory.calls if c[1] >= RING], [("read", RING)]
        )
        self.assert_no_writes()

    def test_ready_checked_on_both_sides_and_full_record_read(self):
        self.memory.publish(1)
        self.reader.poll()
        self.assertEqual(
            [c for c in self.memory.calls if c[1] >= RING],
            [("read", RING), ("bulk", RING, STRIDE), ("read", RING)],
        )

    def test_mismatches_and_short_blob_fail_closed(self):
        for mutation in ("ready", "sequence", "flags", "changed", "short"):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.memory.publish(1)
                if mutation in ("ready", "sequence", "flags"):
                    self.memory.word(
                        RING + {"ready": 0, "sequence": 4, "flags": 12}[mutation], 8
                    )
                elif mutation == "changed":

                    def change(op, address, size):
                        if op == "bulk" and address == RING:
                            self.memory.word(RING, 0)

                    self.memory.hook = change
                else:
                    original = self.memory.read_bulk
                    self.memory.read_bulk = lambda a, n, original=original: (
                        original(a, n)[:-1] if a == RING else original(a, n)
                    )
                with self.assertRaises(TelemetryLoss):
                    self.reader.poll()
                self.assertTrue(self.reader.failed)
                self.assert_no_writes()

    def test_header_changes_between_reads(self):
        for offset, value in ((16, 65), (16, 0), (20, 1), (24, 1), (28, 1)):
            with self.subTest(offset=offset, value=value):
                self.setUp()
                self.memory.publish(1)

                def change(op, address, size, offset=offset, value=value):
                    if op == "bulk" and address == RING:
                        self.memory.word(STATE + offset, value)

                self.memory.hook = change
                with self.assertRaises(TelemetryLoss):
                    self.reader.poll()
                self.assert_no_writes()

    def test_all_fixed_header_fields_checked(self):
        for offset in (0, 4, 8, 12, 28):
            with self.subTest(offset=offset):
                self.setUp()
                self.memory.word(STATE + offset, 99)
                with self.assertRaises(TelemetryLoss):
                    self.reader.poll()

    def test_no_implicit_takeover_and_explicit_resume(self):
        self.memory.word(STATE + 16, 7)
        self.memory.word(STATE + 20, 7)
        with self.assertRaises(TelemetryLoss):
            self.reader.poll()
        with self.assertRaises(TelemetryLoss):
            LiveRingReader(self.memory, STATE, RING, "epoch-1")
        resumed = LiveRingReader(
            self.memory, STATE, RING, "epoch-1", expected_committed_seq=7
        )
        self.assertEqual(resumed.poll().through_seq, 7)
        self.assert_no_writes()

    def test_wrong_epoch_foreign_copied_and_stale_offers_rejected(self):
        first = self.reader.poll()
        latest = self.reader.poll()
        other = LiveRingReader(self.memory, STATE, RING, "epoch-2").poll()
        for offer in (
            first,
            other,
            replace(latest),
            replace(latest, epoch_identity=replace(latest.epoch_identity, token="bad")),
        ):
            with self.assertRaises(TelemetryLoss):
                self.reader.acknowledge(offer)
        self.assert_no_writes()
        self.reader.acknowledge(latest)

    def test_ack_revalidates_consumer_and_loss(self):
        for offset in (20, 24):
            with self.subTest(offset=offset):
                self.setUp()
                self.memory.publish(1)
                offer = self.reader.poll()
                self.memory.word(STATE + offset, 1)
                with self.assertRaises(TelemetryLoss):
                    self.reader.acknowledge(offer)
                self.assertTrue(self.reader.failed)
                self.assert_no_writes()

    def test_uncertain_ack_poisoned_without_retry(self):
        for failure in ("write", "read", "mismatch"):
            with self.subTest(failure=failure):
                self.setUp()
                self.memory.publish(1)
                offer = self.reader.poll()

                def fail(op, address, size, failure=failure):
                    if address != STATE + 20:
                        return
                    if op == failure:
                        raise OSError("transport failed")
                    if failure == "mismatch" and op == "read":
                        self.memory.word(address, 0)

                self.memory.hook = fail
                with self.assertRaises((OSError, TelemetryLoss)):
                    self.reader.acknowledge(offer)
                self.assertTrue(self.reader.failed)
                self.memory.hook = lambda *_: None
                with self.assertRaises(TelemetryLoss):
                    self.reader.acknowledge(offer)
                with self.assertRaises(TelemetryLoss):
                    self.reader.poll()
                self.assertEqual(
                    len([c for c in self.memory.calls if c[0] == "write"]), 1
                )

    def test_poll_transport_failure_can_be_explicitly_retried(self):
        prior = self.reader.poll()

        def fail(*_):
            raise OSError("disconnected")

        self.memory.hook = fail
        with self.assertRaises(OSError):
            self.reader.poll()
        self.assertFalse(self.reader.failed)
        with self.assertRaises(TelemetryLoss):
            self.reader.acknowledge(prior)
        self.memory.hook = lambda *_: None
        self.reader.poll()
        self.assert_no_writes()

    def test_prewrite_transport_failure_can_retry_same_offer(self):
        offer = self.reader.poll()
        self.memory.hook = lambda *_: (_ for _ in ()).throw(OSError("disconnected"))
        with self.assertRaises(OSError):
            self.reader.acknowledge(offer)
        self.assertFalse(self.reader.failed)
        self.assert_no_writes()
        self.memory.hook = lambda *_: None
        self.reader.acknowledge(offer)

    def test_wrap_slot_address_and_counter_regression(self):
        self.memory.word(STATE + 20, 64)
        self.memory.publish(65)
        resumed = LiveRingReader(
            self.memory, STATE, RING, "epoch-1", expected_committed_seq=64
        )
        self.assertEqual(resumed.poll().records[0].sequence, 65)
        self.memory.word(STATE + 16, 64)
        with self.assertRaises(TelemetryLoss):
            resumed.poll()

    def test_full_capacity_is_bounded_and_loss_stays_sticky(self):
        for sequence in range(1, CAPACITY + 1):
            self.memory.publish(sequence)
        offer = self.reader.poll()
        self.assertEqual(len(offer.records), CAPACITY)
        self.assertEqual(offer.through_seq, CAPACITY)
        self.assertEqual(len([c for c in self.memory.calls if c[0] == "bulk"]), 66)
        self.assert_no_writes()
        self.memory.word(STATE + 24, 1)
        with self.assertRaises(TelemetryLoss):
            self.reader.poll()
        self.memory.word(STATE + 24, 0)
        with self.assertRaises(TelemetryLoss):
            self.reader.poll()

    def test_null_offer_is_rejected(self):
        with self.assertRaises(TelemetryLoss):
            self.reader.acknowledge(None)
        self.assert_no_writes()


if __name__ == "__main__":
    unittest.main()
