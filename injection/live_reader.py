"""Bounded live reads for one externally qualified EE producer/host consumer.

The transport must provide ordered, coherent read_bulk/read32/write32 calls.
Ready is published last with target sync, and committed slots must stay immutable
until consumer acknowledgement. This does not qualify EE scheduling, IRQ safety,
cache coherence, or multiple producers. Exclusive host-consumer ownership and no
target reset during this host-provided epoch are external preconditions; the
header has no generation field and cannot detect an otherwise identical reset.

Process an offer durably before acknowledge(). A transport exception *before*
any write propagates and may explicitly be retried by the caller. Failed polls
invalidate older offers. Any write exception or failed confirmation poisons the
reader: never blindly retry a possibly completed write. Protocol loss is sticky.
"""

import struct
from dataclasses import dataclass
from typing import Protocol

from .records import (
    CAPACITY,
    MAGIC,
    RING_SIZE,
    STATE_SIZE,
    STRIDE,
    VERSION,
    Record,
    TelemetryLoss,
    decode_record,
)


class Memory(Protocol):
    def read_bulk(self, address: int, size: int) -> bytes: ...

    def read32(self, address: int) -> int: ...

    def write32(self, address: int, value: int) -> None: ...


@dataclass(frozen=True)
class EpochIdentity:
    token: str | bytes
    state_address: int
    ring_address: int


@dataclass(frozen=True)
class Offer:
    records: tuple[Record, ...]
    through_seq: int
    epoch_identity: EpochIdentity


class LiveRingReader:
    """No automatic takeover, skipping, acknowledgement, or recovery.

    A fresh reader expects consumer zero unless expected_committed_seq is
    explicitly supplied from durable host state. A new successful poll replaces
    the previous offer, even if the records are identical. Offers are capabilities
    local to this exact reader, not reconstructible acknowledgement cursors.
    Calls must be serialized by the single host consumer.
    """

    def __init__(
        self,
        memory: Memory,
        state_address: int,
        ring_address: int,
        epoch_token: str | bytes,
        *,
        expected_committed_seq: int = 0,
    ):
        if not isinstance(epoch_token, (str, bytes)) or not epoch_token:
            raise ValueError("a nonempty immutable host epoch token is required")
        for address, size in ((state_address, STATE_SIZE), (ring_address, RING_SIZE)):
            if (
                type(address) is not int
                or address < 0
                or address % 4
                or address + size > 2**32
            ):
                raise ValueError("invalid fixed memory address")
        if max(state_address, ring_address) < min(
            state_address + STATE_SIZE, ring_address + RING_SIZE
        ):
            raise ValueError("state and ring overlap")
        if (
            type(expected_committed_seq) is not int
            or not 0 <= expected_committed_seq < 2**32
        ):
            raise ValueError("invalid expected committed sequence")
        self._memory = memory
        self._epoch = EpochIdentity(epoch_token, state_address, ring_address)
        self._consumer = expected_committed_seq
        self._producer = expected_committed_seq
        self._latest = None
        self.failed = False
        self._header()

    @property
    def consumer(self):
        return self._consumer

    @property
    def epoch_identity(self):
        return self._epoch

    def _check_active(self):
        if self.failed:
            raise TelemetryLoss("capture epoch already lost")

    def _lose(self, message):
        self.failed = True
        self._latest = None
        raise TelemetryLoss(message)

    def _header(self):
        data = self._memory.read_bulk(self._epoch.state_address, STATE_SIZE)
        if len(data) != STATE_SIZE:
            self._lose("state size mismatch")
        magic, version, capacity, stride, producer, consumer, loss, reserved = (
            struct.unpack("<8I", data)
        )
        if (magic, version, capacity, stride, reserved) != (
            MAGIC,
            VERSION,
            CAPACITY,
            STRIDE,
            0,
        ):
            self._lose("state format mismatch")
        if (
            loss
            or consumer != self._consumer
            or producer < self._producer
            or not 0 <= producer - consumer <= CAPACITY
        ):
            self._lose("capture overflow, reset, or consumer mismatch")
        self._producer = producer
        return producer

    def poll(self) -> Offer:
        self._check_active()
        self._latest = None
        producer = self._header()
        records = []
        cursor = self._consumer
        while cursor < producer:
            address = self._epoch.ring_address + (cursor % CAPACITY) * STRIDE
            expected = cursor + 1
            ready = self._memory.read32(address)
            if ready == 0:
                break
            if ready != expected:
                self._lose("record ready sequence mismatch")
            data = bytes(self._memory.read_bulk(address, STRIDE))
            if self._memory.read32(address) != expected:
                self._lose("committed record changed during read")
            try:
                records.append(decode_record(data, expected))
            except TelemetryLoss as exc:
                self._lose(str(exc))
            cursor += 1
        # Producer may advance while immutable committed records are copied.
        # _header also checks monotonicity, capacity, loss and consumer ownership.
        self._header()
        offer = Offer(tuple(records), cursor, self._epoch)
        self._latest = offer
        return offer

    def acknowledge(self, offer: Offer) -> None:
        self._check_active()
        if (
            not isinstance(offer, Offer)
            or offer is not self._latest
            or offer.epoch_identity != self._epoch
        ):
            raise TelemetryLoss("acknowledgement requires this reader's latest offer")
        # A pre-write transport failure is safe to retry explicitly. A protocol
        # failure here poisons the reader without touching target memory.
        self._header()
        address = self._epoch.state_address + 20
        try:
            self._memory.write32(address, offer.through_seq)
            if self._memory.read32(address) != offer.through_seq:
                raise TelemetryLoss("consumer acknowledgement readback mismatch")
        except BaseException:
            self.failed = True
            self._latest = None
            raise
        self._consumer = offer.through_seq
        self._latest = None
