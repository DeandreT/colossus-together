"""Single-owner, single-outstanding-command protocol over read32/write32.

The memory adapter may be runtime.pine.PineClient. It must provide coherent,
ordered, bounded I/O. This module never connects, pauses, retries, or installs.
"""

import math
import threading
import time
from dataclasses import dataclass

from runtime.pine import check_range

SIZE = 96
REQUEST, REPLY, BUSY, LAST = 0, 4, 8, 12
INDEX, OP, ARGS, FLOATS = 16, 20, 24, 56
STATUS, V0, V1, F0, FAULT = 68, 72, 76, 80, 84
MAX_SEQUENCE = 0xFFFFFFFF
CALL = 1


def u32(value):
    if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
        raise ValueError("expected uint32 (float registers use raw IEEE-754 bits)")
    return value


class ProtocolError(RuntimeError):
    pass


class Pending(TimeoutError):
    """Completion is unknown. Only observe this same command; never resubmit."""


@dataclass(frozen=True)
class Call:
    index: int
    args: tuple = (0,) * 8
    floats: tuple = (0,) * 3

    def __post_init__(self):
        u32(self.index)
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "floats", tuple(self.floats))
        if len(self.args) != 8 or len(self.floats) != 3:
            raise ValueError("CALL requires exactly eight GPR and three FPR words")
        for value in (*self.args, *self.floats):
            u32(value)


@dataclass(frozen=True)
class Reply:
    sequence: int
    status: int
    v0: int
    v1: int
    f0: int


class Host:
    """One instance owns a fresh/idle mailbox for its entire installation.

    External writers, reconnect/adoption during pending work, and sequence reset
    are not supported. After write/read errors inspect pending_sequence and use
    wait(), never a second submit(). A new installation is needed at exhaustion.
    """

    def __init__(self, memory, base, *, table_size):
        check_range(base, SIZE, 16)
        if type(table_size) is not int or not 1 <= table_size <= 256:
            raise ValueError("table must contain 1..256 entries")
        self.memory, self.base, self.table_size = memory, base, table_size
        self._lock = threading.RLock()
        self.pending_sequence = None
        request, reply, busy, last, fault = self._state()
        if busy or fault or request != reply or request != last:
            raise ProtocolError("cannot adopt non-idle/faulted mailbox")
        self._last = last

    def _read(self, offset):
        return u32(self.memory.read32(self.base + offset))

    def _state(self):
        before = self._read(REQUEST)
        state = tuple(self._read(x) for x in (REPLY, BUSY, LAST, FAULT))
        if self._read(REQUEST) != before:
            raise ProtocolError("mailbox changed: exclusive ownership required")
        return (before, *state)

    def submit(self, command):
        with self._lock:
            if not isinstance(command, Call) or command.index >= self.table_size:
                raise ValueError("CALL index outside approved table")
            if self.pending_sequence is not None:
                raise ProtocolError("prior command completion remains unknown")
            if self._state() != (self._last, self._last, 0, self._last, 0):
                raise ProtocolError("mailbox not idle or changed externally")
            if self._last == MAX_SEQUENCE:
                raise ProtocolError("sequence exhausted; reinstall, never wrap")
            sequence = self._last + 1
            # Even a payload write failure may be partial; fail closed locally.
            self.pending_sequence = sequence
            for offset, value in (
                (INDEX, command.index),
                (OP, CALL),
                *((ARGS + i * 4, value) for i, value in enumerate(command.args)),
                *((FLOATS + i * 4, value) for i, value in enumerate(command.floats)),
                (REQUEST, sequence),  # Publication is strictly last.
            ):
                self.memory.write32(self.base + offset, value)
            return sequence

    def wait(self, *, timeout=2.0, interval=0.001):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("positive finite timeout required")
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("positive finite interval required")
        with self._lock:
            sequence = self.pending_sequence
            if sequence is None:
                raise ProtocolError("no command pending")
            deadline = time.monotonic() + timeout
            while True:
                if self._read(FAULT):
                    raise ProtocolError("dispatcher fault; completion unknown")
                committed = self._read(REPLY)
                if committed == sequence:
                    result = Reply(
                        sequence, *(self._read(x) for x in (STATUS, V0, V1, F0))
                    )
                    if self._read(REPLY) != sequence:
                        raise ProtocolError("reply changed externally")
                    self._last = sequence
                    self.pending_sequence = None
                    return result
                if committed != self._last:
                    raise ProtocolError("unexpected reply sequence")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Pending(
                        f"sequence {sequence} completion unknown; not retried"
                    )
                time.sleep(min(interval, remaining))
