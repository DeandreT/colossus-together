"""Small, bounded PCSX2 PINE client; no discovery or automatic connection."""

import math
import socket
import struct
import threading
import time
from enum import IntEnum

EE_RAM_SIZE = 32 * 1024 * 1024
MAX_REQUEST = 650000
MAX_REPLY = 450000


class PineError(Exception):
    pass


class Status(IntEnum):
    RUNNING = 0
    PAUSED = 1
    SHUTDOWN = 2


def check_range(address, size, alignment=1):
    if (
        not isinstance(address, int)
        or not isinstance(size, int)
        or address < 0
        or size < 0
        or address + size > EE_RAM_SIZE
        or address % alignment
    ):
        raise ValueError("address/size outside aligned physical EE RAM")


class PineClient:
    def __init__(
        self,
        path,
        *,
        timeout=2.0,
        max_request=MAX_REQUEST,
        max_reply=MAX_REPLY - 1,
        max_bulk=1024 * 1024,
    ):
        if not isinstance(path, str) or not path or not path.startswith("/"):
            raise ValueError("an explicit absolute Unix socket path is required")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        if (
            not isinstance(max_request, int)
            or not isinstance(max_reply, int)
            or not 13 <= max_request <= MAX_REQUEST
            or not 14 <= max_reply < MAX_REPLY
        ):
            # PCSX2 rejects replies reaching MAX_IPC_RETURN_SIZE.
            raise ValueError("invalid frame limits")
        if not isinstance(max_bulk, int) or not 0 < max_bulk <= EE_RAM_SIZE:
            raise ValueError("invalid bulk limit")
        self.path, self.timeout = path, timeout
        self.max_request, self.max_reply = max_request, max_reply
        self.max_bulk = max_bulk
        self._socket = None
        self._lock = threading.RLock()

    def close(self):
        with self._lock:
            if self._socket is not None:
                self._socket.close()
                self._socket = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _request(self, commands, expected=None):
        if not commands or len(commands) + 4 > self.max_request:
            raise ValueError("request exceeds frame limit")
        with self._lock:
            deadline = time.monotonic() + self.timeout

            def remaining():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("PINE operation deadline exceeded")
                self._socket.settimeout(left)

            def receive(count):
                data = bytearray()
                while len(data) < count:
                    remaining()
                    part = self._socket.recv(count - len(data))
                    if not part:
                        raise PineError("PINE connection ended mid-frame")
                    data.extend(part)
                return bytes(data)

            try:
                if self._socket is None:
                    self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    remaining()
                    self._socket.connect(self.path)
                remaining()
                self._socket.sendall(struct.pack("<I", len(commands) + 4) + commands)
                (length,) = struct.unpack("<I", receive(4))
                if not 5 <= length <= self.max_reply:
                    raise PineError("invalid/oversized PINE reply frame")
                body = receive(length - 4)
                if body[0] != 0:
                    raise PineError("PINE command rejected (writes may be partial)")
                result = body[1:]
                if expected is not None and len(result) != expected:
                    raise PineError("unexpected PINE reply size")
                return result
            except (OSError, PineError):
                self.close()  # Never retry writes or reuse a desynchronized stream.
                raise

    def _read(self, address, width, opcode):
        check_range(address, width, width)
        return int.from_bytes(
            self._request(struct.pack("<BI", opcode, address), width), "little"
        )

    def read8(self, address):
        return self._read(address, 1, 0)

    def read32(self, address):
        return self._read(address, 4, 2)

    def read64(self, address):
        return self._read(address, 8, 3)

    def read_bulk(self, address, size):
        """Read bytes using bounded batches of Read8 (works at unaligned edges)."""
        check_range(address, size)
        if size > self.max_bulk:
            raise ValueError("bulk read exceeds configured operation limit")
        batch = min((self.max_request - 4) // 5, self.max_reply - 5)
        out = bytearray()
        with self._lock:
            for offset in range(0, size, batch):
                count = min(batch, size - offset)
                commands = b"".join(
                    struct.pack("<BI", 0, address + offset + i) for i in range(count)
                )
                out.extend(self._request(commands, count))
        return bytes(out)

    def write32(self, address, value):
        """Range/value checked primitive, not an identity or expected-word guard."""
        check_range(address, 4, 4)
        if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("word must be uint32")
        self._request(struct.pack("<BII", 6, address, value), 0)

    def _string(self, opcode):
        data = self._request(bytes([opcode]))
        try:
            if len(data) < 5:
                raise ValueError()
            (length,) = struct.unpack_from("<I", data)
            if length != len(data) - 4 or data[-1] != 0 or b"\0" in data[4:-1]:
                raise ValueError()
            return data[4:-1].decode("utf-8", errors="strict")
        except (ValueError, UnicodeError) as exc:
            self.close()
            raise PineError("invalid PINE string") from exc

    def uuid(self):
        return self._string(0xD)

    def title(self):
        return self._string(0xB)

    def status(self):
        try:
            return Status(struct.unpack("<I", self._request(b"\x0f", 4))[0])
        except ValueError as exc:
            self.close()
            raise PineError("unknown emulator status") from exc
