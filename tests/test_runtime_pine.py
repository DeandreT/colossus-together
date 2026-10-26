import socket
import struct

import pytest

from runtime.pine import EE_RAM_SIZE, PineClient, PineError, Status


def reply(data=b"", status=0):
    return struct.pack("<IB", len(data) + 5, status) + data


class FakeSocket:
    def __init__(self, wire, *, fragment=1, error=None):
        self.wire = bytearray(wire)
        self.fragment = fragment
        self.error = error
        self.sent = []
        self.closed = False
        self.timeouts = []

    def connect(self, path):
        self.path = path

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, count):
        if self.error:
            raise self.error
        count = min(count, self.fragment)
        data = self.wire[:count]
        del self.wire[:count]
        return bytes(data)

    def close(self):
        self.closed = True


def client(monkeypatch, wire, **kwargs):
    fake = FakeSocket(wire)
    calls = []

    def factory(*args):
        calls.append(args)
        return fake

    monkeypatch.setattr(socket, "socket", factory)
    return PineClient("/explicit/test.sock", **kwargs), fake, calls


def test_fragmented_reads_persistent_connection(monkeypatch):
    c, fake, calls = client(
        monkeypatch,
        reply(b"\x7f")
        + reply(struct.pack("<I", 42))
        + reply(struct.pack("<Q", 1 << 48)),
    )
    with c:
        assert c.read8(3) == 127
        assert c.read32(4) == 42
        assert c.read64(8) == 1 << 48
    assert len(calls) == 1 and fake.closed
    assert fake.path == "/explicit/test.sock"
    assert fake.sent[1] == struct.pack("<IBI", 9, 2, 4)
    assert all(0 < t <= 2 for t in fake.timeouts)


def test_queries_and_write(monkeypatch):
    def text(value):
        data = value.encode() + b"\0"
        return reply(struct.pack("<I", len(data)) + data)

    c, fake, _ = client(
        monkeypatch,
        text("c19a374e") + text("SotC") + reply(struct.pack("<I", 1)) + reply(),
    )
    assert c.uuid() == "c19a374e"
    assert c.title() == "SotC"
    assert c.status() == Status.PAUSED
    c.write32(4, 0xDEADBEEF)
    assert fake.sent[-1] == struct.pack("<IBII", 13, 6, 4, 0xDEADBEEF)


def test_bulk_batches_and_edges(monkeypatch):
    c, fake, _ = client(monkeypatch, reply(b"abc") + reply(b"de"), max_request=19)
    assert c.read_bulk(EE_RAM_SIZE - 5, 5) == b"abcde"
    assert len(fake.sent) == 2
    assert c.read_bulk(EE_RAM_SIZE, 0) == b""


@pytest.mark.parametrize(
    "wire",
    [
        struct.pack("<I", 4),
        struct.pack("<I", 450000),
        reply(b"x", 255),
        reply(b"xx"),
        b"\x06\0",
        struct.pack("<IB", 6, 0),
        reply(b"", 7),
    ],
)
def test_bad_replies_close(monkeypatch, wire):
    c, fake, _ = client(monkeypatch, wire)
    with pytest.raises(PineError):
        c.read8(0)
    assert fake.closed


def test_timeout_not_retried(monkeypatch):
    c, fake, calls = client(monkeypatch, b"")
    fake.error = TimeoutError("fake timeout")
    with pytest.raises(TimeoutError):
        c.write32(0, 1)
    assert fake.closed and len(calls) == 1 and len(fake.sent) == 1


def test_whole_frame_deadline(monkeypatch):
    c, fake, _ = client(monkeypatch, reply(b"a"), timeout=1)
    ticks = iter([0, 0.1, 0.2, 0.3, 1.1])
    monkeypatch.setattr("runtime.pine.time.monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        c.read8(0)
    assert fake.closed


@pytest.mark.parametrize(
    "method,args",
    [
        ("read8", (-1,)),
        ("read32", (2,)),
        ("read64", (EE_RAM_SIZE,)),
        ("read_bulk", (EE_RAM_SIZE - 1, 2)),
        ("read_bulk", (0, 1048577)),
        ("write32", (0, 1 << 32)),
        ("write32", (EE_RAM_SIZE, 0)),
    ],
)
def test_bounds_before_socket(monkeypatch, method, args):
    c, _, calls = client(monkeypatch, b"")
    with pytest.raises(ValueError):
        getattr(c, method)(*args)
    assert not calls


@pytest.mark.parametrize(
    "data",
    [
        b"",
        struct.pack("<I", 1) + b"x",
        struct.pack("<I", 2) + b"\xff\0",
        struct.pack("<I", 3) + b"\0x\0",
    ],
)
def test_malformed_strings(monkeypatch, data):
    c, fake, _ = client(monkeypatch, reply(data))
    with pytest.raises(PineError):
        c.uuid()
    assert fake.closed


def test_unknown_status(monkeypatch):
    c, fake, _ = client(monkeypatch, reply(struct.pack("<I", 3)))
    with pytest.raises(PineError):
        c.status()
    assert fake.closed


@pytest.mark.parametrize(
    "options",
    [
        {"path": "relative"},
        {"timeout": 0},
        {"timeout": float("inf")},
        {"max_reply": 450000},
        {"max_request": 12},
        {"max_bulk": 0},
    ],
)
def test_constructor_limits(options):
    with pytest.raises(ValueError):
        PineClient(**({"path": "/socket"} | options))


def test_frame_limits_must_be_integers():
    with pytest.raises(ValueError):
        PineClient("/socket", max_request=20.5)


def test_final_valid_ee_words(monkeypatch):
    c, _, _ = client(monkeypatch, reply(struct.pack("<Q", 123)) + reply())
    assert c.read64(EE_RAM_SIZE - 8) == 123
    c.write32(EE_RAM_SIZE - 4, 0xFFFFFFFF)
