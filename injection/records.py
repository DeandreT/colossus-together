"""Versioned little-endian capture format and fail-closed host reader."""

import struct
from dataclasses import dataclass
from enum import IntEnum

MAGIC = 0x504F4F43  # COOP
VERSION = 2
CAPACITY = 64
STRIDE = 256
STATE_SIZE = 32
RING_SIZE = CAPACITY * STRIDE
PARAM_OFFSET, PARAM_SIZE = 64, 0x3C
GP_OFFSET, GP_SIZE = 128, 0x40
PARAM_MISSING, GP_INVALID, ALLOCATION_INVALID = 1, 2, 4
ALLOCATION_OFFSET = 0x7C


class Kind(IntEnum):
    SCRIPT_CHAR = 1
    ALIAS_LAYOUT = 2
    DELETE_REQUEST = 3
    FINAL_FREE_ALLOCATION = 4


class TelemetryLoss(ValueError):
    """Sticky loss: this capture epoch cannot authorize activation."""


def initial_state():
    return struct.pack("<8I", MAGIC, VERSION, CAPACITY, STRIDE, 0, 0, 0, 0)


@dataclass(frozen=True)
class Record:
    sequence: int
    kind: Kind
    flags: int
    object_ptr: int
    arguments: tuple[int, ...]
    gp_ptr: int
    parameters: bytes
    gp_bytes: bytes
    allocation_ptr: int = 0

    @property
    def definition_ptr(self):
        return self.arguments[1]

    @property
    def alias_source(self):
        return self.arguments[4] if self.kind == Kind.ALIAS_LAYOUT else None


def decode_record(data, expected_sequence):
    if len(data) != STRIDE:
        raise TelemetryLoss("record size mismatch")
    ready, sequence, kind, flags, obj, gp, param_len, gp_len = struct.unpack_from(
        "<8I", data
    )
    if ready != expected_sequence or sequence != expected_sequence:
        raise TelemetryLoss("record sequence mismatch")
    try:
        kind = Kind(kind)
    except ValueError as exc:
        raise TelemetryLoss("unknown record kind") from exc
    if flags & ~(PARAM_MISSING | GP_INVALID | ALLOCATION_INVALID):
        raise TelemetryLoss("unknown record flags")
    (allocation,) = struct.unpack_from("<I", data, ALLOCATION_OFFSET)
    arguments = struct.unpack_from("<8I", data, 32)
    if kind in (Kind.DELETE_REQUEST, Kind.FINAL_FREE_ALLOCATION):
        if flags or gp or param_len or gp_len:
            raise TelemetryLoss("invalid lifetime record")
        if (
            kind == Kind.DELETE_REQUEST
            and (allocation or obj != arguments[0])
            or kind == Kind.FINAL_FREE_ALLOCATION
            and (obj or allocation != arguments[0])
        ):
            raise TelemetryLoss("invalid lifetime identity fields")
    elif (
        param_len != (0 if flags & PARAM_MISSING else PARAM_SIZE)
        or gp_len != (GP_SIZE if gp and not flags & GP_INVALID else 0)
        or flags & PARAM_MISSING
        and (gp or gp_len)
        or flags & GP_INVALID
        and not gp
    ):
        raise TelemetryLoss("invalid snapshot lengths")
    elif kind in (Kind.SCRIPT_CHAR, Kind.ALIAS_LAYOUT):
        invalid_object = bool(obj and (obj % 4 or not 0x80000 <= obj <= 0x1FFFFFC))
        if (
            bool(flags & ALLOCATION_INVALID) != invalid_object
            or (not obj or invalid_object)
            and allocation
        ):
            raise TelemetryLoss("invalid allocation snapshot")
    return Record(
        sequence,
        kind,
        flags,
        obj,
        arguments,
        gp,
        bytes(data[PARAM_OFFSET : PARAM_OFFSET + param_len]),
        bytes(data[GP_OFFSET : GP_OFFSET + gp_len]),
        allocation,
    )


class RingReader:
    """Consume a coherent, paused snapshot, then explicitly acknowledge it.

    No live memory I/O. Caller writes consumer only after dispatch succeeds.
    Pending outer calls block draining their already-completed nested calls.
    Loss is sticky even if a later snapshot clears the target's loss word.
    """

    def __init__(self):
        self.consumer = 0
        self.failed = False
        self._offered = 0

    def drain(self, state, ring):
        if self.failed:
            raise TelemetryLoss("capture epoch already lost")
        try:
            if len(state) != STATE_SIZE or len(ring) != RING_SIZE:
                raise TelemetryLoss("snapshot size mismatch")
            magic, version, capacity, stride, producer, consumer, loss, reserved = (
                struct.unpack("<8I", state)
            )
            if (magic, version, capacity, stride, reserved) != (
                MAGIC,
                VERSION,
                CAPACITY,
                STRIDE,
                0,
            ):
                raise TelemetryLoss("state format mismatch")
            if (
                loss
                or consumer != self.consumer
                or producer < consumer
                or producer - consumer > CAPACITY
            ):
                raise TelemetryLoss("capture overflow, reset, or consumer mismatch")
            result = []
            cursor = consumer
            while cursor < producer:
                offset = (cursor % CAPACITY) * STRIDE
                data = ring[offset : offset + STRIDE]
                if struct.unpack_from("<I", data)[0] == 0:
                    break
                result.append(decode_record(data, cursor + 1))
                cursor += 1
            self._offered = cursor
            return tuple(result), cursor
        except (TelemetryLoss, struct.error) as exc:
            self.failed = True
            raise TelemetryLoss(str(exc)) from exc

    def acknowledge(self, cursor):
        if self.failed or not self.consumer <= cursor <= self._offered:
            raise TelemetryLoss("invalid acknowledgement")
        self.consumer = cursor
