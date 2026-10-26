"""Execute generated source with modeled R5900 register width and delay slots.

This is deliberately not an EE emulator/ABI qualification. Real assembly is
separately tested when PS2 binutils are available.
"""

import hashlib
import re

import pytest

from commands.generator import FRAME, GPRS, USB_ENTRY, Config, Target, guards, render
from commands.protocol import Call, Host, Pending, ProtocolError


def configuration(**changes):
    values = {
        "gamecore": 0x100000,
        "original_usb": 0x500000 + 0xD05F0,
        "usb_entry": USB_ENTRY,
        "delay_word": 0,
        "code": 0x1400000,
        "mailbox": 0x1500000,
        "executable": ((0x100000, 0x200000), (0x500000, 0x600000)),
        "targets": (Target(0x110000, 0x600000), Target(0x120000, 0x600000)),
    }
    values.update(changes)
    return Config(**values)


class Memory:
    def __init__(self):
        self.words = {}
        self.writes = []

    def read32(self, address):
        return self.words.get(address, 0)

    def write32(self, address, value):
        self.words[address] = value & 0xFFFFFFFF
        self.writes.append((address, value & 0xFFFFFFFF))


class NonlocalExit(Exception):
    pass


class Machine:
    def __init__(self, config=None, memory=None):
        self.config = config or configuration()
        self.memory = memory or Memory()
        source = render(self.config, guards(self.config))
        self.code, self.labels = [], {}
        for line in source.splitlines():
            if line.endswith(":"):
                self.labels[line[:-1]] = len(self.code)
            elif line.startswith(".word"):
                for value in line[6:].split(","):
                    self.code.append((".word", int(value, 0)))
            elif not line.startswith("."):
                self.code.append(tuple(re.split(r"[ ,]+", line)))
        self.table_address = 0x1402000
        for i, target in enumerate(self.config.targets):
            self.memory.words[self.table_address + i * 8] = target.address
            self.memory.words[self.table_address + i * 8 + 4] = target.gp
        self.gpr = {r: ((i + 1) << 100) | (0x100 + i) for i, r in enumerate(GPRS)}
        self.gpr["zero"], self.gpr["sp"] = 0, (0x987 << 80) | 0x1800000
        self.fpr = list(range(100, 132))
        self.special = {"hi": 11, "lo": 12, "hi1": 13, "lo1": 14, "sa": 15, "fcsr": 16}
        self.callbacks, self.usb_count, self.delay_count = {}, 0, 0

    def get(self, reg):
        return self.gpr[reg.removeprefix("$")]

    def low(self, reg):
        return self.get(reg) & 0xFFFFFFFF

    def set(self, reg, value):
        key = reg.removeprefix("$")
        if key != "zero":
            self.gpr[key] = (self.gpr[key] & ~((1 << 64) - 1)) | (
                value & ((1 << 64) - 1)
            )

    def address(self, operand):
        offset, reg = operand.split("(")
        address = (self.low(reg[:-1]) + int(offset)) & 0xFFFFFFFF
        return address & 0x1FFFFFFF if address & 0xE0000000 == 0xA0000000 else address

    def step(self, ins):
        op, *a = ins
        if op == "nop":
            return
        if op == "sync":
            self.memory.writes.append(("sync", 0))
        elif op in ("sq", "sd", "sw"):
            address = self.address(a[1])
            size = {"sq": 16, "sd": 8, "sw": 4}[op]
            value = self.get(a[0])
            for i in range(size // 4):
                self.memory.write32(address + i * 4, (value >> (i * 32)) & 0xFFFFFFFF)
        elif op in ("lq", "ld", "lw"):
            address = self.address(a[1])
            size = {"lq": 16, "ld": 8, "lw": 4}[op]
            value = sum(
                self.memory.read32(address + i * 4) << (i * 32)
                for i in range(size // 4)
            )
            if op == "lq":
                self.gpr[a[0][1:]] = value
            else:
                if op == "lw" and value & 0x80000000:
                    value |= 0xFFFFFFFF00000000
                self.set(a[0], value)
        elif op in ("swc1", "lwc1"):
            reg = int(a[0][2:])
            if op == "swc1":
                self.memory.write32(self.address(a[1]), self.fpr[reg])
            else:
                self.fpr[reg] = self.memory.read32(self.address(a[1]))
        elif op == "lui":
            value = self.table_address >> 16 if "%hi" in a[1] else int(a[1], 0)
            self.set(a[0], value << 16)
        elif op in ("addiu", "ori", "andi", "sll", "sltiu"):
            value = self.table_address & 0xFFFF if "%lo" in a[2] else int(a[2], 0)
            src = self.low(a[1])
            result = {
                "addiu": lambda: src + value,
                "ori": lambda: src | value,
                "andi": lambda: src & value,
                "sll": lambda: src << value,
                "sltiu": lambda: int(src < value),
            }[op]()
            self.set(a[0], result & 0xFFFFFFFF)
        elif op == "daddu":
            self.set(a[0], self.get(a[1]) + self.get(a[2]))
        elif op in ("addu", "sltu"):
            result = (
                self.low(a[1]) + self.low(a[2])
                if op == "addu"
                else int(self.low(a[1]) < self.low(a[2]))
            )
            self.set(a[0], result & 0xFFFFFFFF)
        elif op in ("mfhi", "mflo", "mfhi1", "mflo1", "mfsa"):
            self.set(a[0], self.special[op[2:]])
        elif op in ("mthi", "mtlo", "mthi1", "mtlo1", "mtsa"):
            self.special[op[2:]] = self.get(a[0]) & (
                (1 << (32 if op == "mtsa" else 64)) - 1
            )
        elif op == "cfc1":
            self.set(a[0], self.special["fcsr"])
        elif op == "ctc1":
            self.special["fcsr"] = self.low(a[0])
        else:
            raise AssertionError(ins)

    def run(self):
        pc = self.labels["command_dispatch"]
        for _ in range(2000):
            ins = self.code[pc]
            op, *args = ins
            if op in ("beq", "bne", "b", "jalr", "j"):
                if op in ("beq", "bne"):
                    equal = self.low(args[0]) == self.low(args[1])
                    take = equal if op == "beq" else not equal
                    destination = self.labels[args[2]] if take else pc + 2
                elif op == "b":
                    destination = self.labels[args[0]]
                else:
                    destination = None
                # Branch operands/call target evaluated BEFORE the delay slot.
                target = self.low(args[1]) if op == "jalr" else None
                self.step(self.code[pc + 1])
                self.delay_count += 1
                if op == "j":
                    assert args == ["original_USB"]
                    self.usb_count += 1
                    return
                if op == "jalr":
                    self.set("$ra", pc + 2)
                    self.callbacks[target](self)
                    destination = pc + 2
                pc = destination
            else:
                self.step(ins)
                pc += 1
        raise AssertionError("dispatch did not terminate")


@pytest.mark.parametrize("target_stack", [None, (0x1600000, 0x4000)])
def test_command_abi_context_and_commit_order(target_stack):
    machine = Machine(configuration(target_stack=target_stack))
    host = Host(machine.memory, machine.config.mailbox, table_size=2)
    host.submit(
        Call(
            0,
            tuple(range(0xFFFFFFF8, 0x100000000)),
            (0x3F800000, 0x40000000, 0x40400000),
        )
    )
    saved = (dict(machine.gpr), list(machine.fpr), dict(machine.special))
    calls = []

    def command(m):
        calls.append(1)
        assert [
            m.low("$" + r) for r in ("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3")
        ] == list(range(0xFFFFFFF8, 0x100000000))
        assert m.fpr[12:15] == [0x3F800000, 0x40000000, 0x40400000]
        assert m.low("$gp") == 0x600000
        if target_stack is None:
            assert m.low("$sp") == 0x1800000 - FRAME
        else:
            base, size = target_stack
            assert m.low("$sp") == base + size - 80
            assert m.low("$sp") % 16 == 0
            # A callee can overwrite all outgoing home space, descend well past
            # the native 4 KiB stack budget, and trash caller-saved temporaries.
            top = m.low("$sp")
            for address in range(top - 0x2800, top + 64, 4):
                assert base <= address < base + size
                assert not 0x1800000 - FRAME <= address < 0x1800000
                m.memory.write32(address, 0xDEADBEEF)
            m.set("$sp", top - 0x2800)
            m.set("$sp", top)
        for reg in GPRS:
            if reg not in ("zero", "sp"):
                m.gpr[reg] = (1 << 127) + 88
        m.fpr = [999] * 32
        m.special = dict.fromkeys(m.special, 444)
        m.set("$v0", 123)
        m.set("$v1", 456)
        m.fpr[0] = 0x3F800000

    machine.callbacks[0x110000] = command
    machine.run()
    assert (machine.gpr, machine.fpr, machine.special) == saved
    assert machine.usb_count == 1 and machine.delay_count > 0
    reply = host.wait()
    assert (reply.sequence, reply.status, reply.v0, reply.v1, reply.f0) == (
        1,
        0,
        123,
        456,
        0x3F800000,
    )
    commits = [
        i
        for i, (a, v) in enumerate(machine.memory.writes)
        if a == machine.config.mailbox + 4
    ]
    assert len(commits) == 1
    assert machine.memory.writes[commits[0] - 1] == ("sync", 0)
    machine.run()
    assert machine.usb_count == 2  # Duplicate sequence: USB still runs, CALL doesn't.
    assert calls == [1]


@pytest.mark.parametrize("target_stack", [None, (0x1600000, 0x4000)])
def test_reentry_and_nonlocal_exit_remain_pending(target_stack):
    machine = Machine(configuration(target_stack=target_stack))
    host = Host(machine.memory, machine.config.mailbox, table_size=2)
    host.submit(Call(0))
    calls = []

    def command(m):
        calls.append(1)
        m.run()  # A yielded call reenters dispatcher with BUSY already set.
        assert m.usb_count == 1
        raise NonlocalExit()

    machine.callbacks[0x110000] = command
    with pytest.raises(NonlocalExit):
        machine.run()
    if target_stack is not None:
        assert machine.low("$sp") == sum(target_stack) - 80
    machine.run()
    assert calls == [1] and machine.usb_count == 2
    assert machine.memory.read32(machine.config.mailbox + 8) == 1
    with pytest.raises(Pending):
        host.wait(timeout=0.001)
    with pytest.raises(ProtocolError):
        host.submit(Call(0))


@pytest.mark.parametrize("target_stack", [None, (0x1600000, 0x4000)])
def test_returning_reentry_runs_once_then_allows_next_sequence(target_stack):
    m = Machine(configuration(target_stack=target_stack))
    host = Host(m.memory, m.config.mailbox, table_size=2)
    calls = []

    def command(machine):
        calls.append(1)
        machine.run()
        machine.set("$v0", 99)

    m.callbacks[0x110000] = command
    for sequence in (1, 2):
        assert host.submit(Call(0)) == sequence
        m.run()
        assert host.wait().v0 == 99
    assert calls == [1, 1] and m.usb_count == 4


@pytest.mark.parametrize(
    "stack,expected",
    [
        (None, "3a09d50920712d01673a8ff7ec8aa4ac0c941095c8ada489ec4348a309a89397"),
        (
            (0x1600000, 0x4000),
            "29eeedc368ca8d524cc2182ec27b60ce6f4e2aa3198a30cb32a462180ed0dac5",
        ),
    ],
)
def test_default_generated_source_is_unchanged(stack, expected):
    config = configuration(target_stack=stack)
    assert config.frame_callback is None
    assert (
        hashlib.sha256(render(config, guards(config)).encode()).hexdigest() == expected
    )


@pytest.mark.parametrize(
    "target_stack",
    [
        (0x81600000, 0x4000),
        (0xA1600000, 0x4000),
        (0x1600004, 0x4000),
        (0x1600000, 0x1FF0),
        (0x1600000, 0x10010),
        (0x1600000, 0x2001),
        (0x1FFF000, 0x2000),
        (0x70000, 0x4000),
        (0x1400000, 0x4000),
        (0x13FE000, 0x4000),
        (0x1500000, 0x4000),
        (0x14FE010, 0x2000),
        (0x110000, 0x4000),
        (0xFF000, 0x2000),
        (0x1600000,),
        (0x1600000, 0x4000, 0),
        "bad",
        (True, 0x4000),
        (0x1600000, 8192.0),
    ],
)
def test_invalid_target_stack_rejected(target_stack):
    with pytest.raises(ValueError):
        configuration(target_stack=target_stack)


def test_target_stack_boundaries_and_previous_dispatch():
    for base, size in [(0x1600000, 0x2000), (0x1FF0000, 0x10000)]:
        assert configuration(target_stack=(base, size)).target_stack == (base, size)
    for previous in (0x1600000, 0x1601FFC):
        with pytest.raises(ValueError, match="replacement storage"):
            configuration(target_stack=(0x1600000, 0x2000), previous_dispatch=previous)
    configuration(target_stack=(0x1600000, 0x2000), previous_dispatch=0x1602000)


def frame_configuration(**changes):
    return configuration(
        **{
            "target_stack": (0x1600000, 0x8000),
            "frame_callback": Target(0x130000, 0x610000),
            **changes,
        }
    )


def clobber_context(machine):
    for reg in GPRS:
        if reg not in ("zero", "sp"):
            machine.gpr[reg] = (1 << 127) | 0xDEADBEEF
    machine.fpr = [0xBAD] * 32
    machine.special = dict.fromkeys(machine.special, 0xBAD)


def test_idle_frame_callback_private_stack_reentry_and_prior_reply():
    m = Machine(frame_configuration())
    for offset, value in (
        (0, 7),
        (4, 7),
        (12, 7),
        (68, 2),
        (72, 11),
        (76, 12),
        (80, 13),
    ):
        m.memory.words[m.config.mailbox + offset] = value
    previous = {
        offset: m.memory.read32(m.config.mailbox + offset)
        for offset in (0, 4, 12, 68, 72, 76, 80)
    }
    saved = (dict(m.gpr), list(m.fpr), dict(m.special))
    calls = []

    def frame(machine):
        calls.append("frame")
        assert machine.low("$gp") == 0x610000
        top = sum(machine.config.target_stack) - 80
        assert machine.low("$sp") == top
        assert machine.memory.read32(machine.config.mailbox + 8) == 1
        # Descend 8 KiB, write the callee's own frame and the outgoing home area.
        for address in range(top - 0x2000, top + 64, 4):
            machine.memory.write32(address, 0x12345678)
        machine.set("$sp", top - 0x2000)
        count = len(calls)
        machine.run()
        assert len(calls) == count  # Nested dispatch did not call us.
        assert machine.low("$sp") == top - 0x2000
        assert machine.low("$gp") == 0x610000
        machine.set("$sp", top)
        clobber_context(machine)

    m.callbacks[0x130000] = frame
    for count in (1, 2):
        m.run()
        assert calls == ["frame"] * count
        assert m.usb_count == count * 2  # One nested and one outer tail call.
        assert (m.gpr, m.fpr, m.special) == saved
        assert m.memory.read32(m.config.mailbox + 8) == 0
        assert previous == {
            offset: m.memory.read32(m.config.mailbox + offset) for offset in previous
        }


@pytest.mark.parametrize("bad_operation", [False, True])
def test_command_then_frame_defers_reply_and_preserves_results(bad_operation):
    m = Machine(frame_configuration())
    host = Host(m.memory, m.config.mailbox, table_size=2)
    host.submit(Call(0, tuple(range(8))))
    if bad_operation:
        m.memory.words[m.config.mailbox + 20] = 99
    saved = (dict(m.gpr), list(m.fpr), dict(m.special))
    events = []

    def command(machine):
        events.append("command")
        assert [
            machine.low("$" + reg)
            for reg in ("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3")
        ] == list(range(8))
        assert machine.low("$gp") == 0x600000
        assert machine.low("$sp") == sum(machine.config.target_stack) - 80
        machine.set("$v0", 123)
        machine.set("$v1", 456)
        machine.fpr[0] = 789

    def frame(machine):
        events.append("frame")
        assert machine.low("$gp") == 0x610000
        assert machine.low("$sp") == sum(machine.config.target_stack) - 80
        assert machine.memory.read32(machine.config.mailbox + 8) == 1
        assert machine.memory.read32(machine.config.mailbox + 4) == 0
        with pytest.raises(Pending):
            host.wait(timeout=0.001)
        with pytest.raises(ProtocolError):
            host.submit(Call(1))
        machine.run()
        clobber_context(machine)

    m.callbacks.update({0x110000: command, 0x130000: frame})
    m.run()
    assert events == (["frame"] if bad_operation else ["command", "frame"])
    assert (m.gpr, m.fpr, m.special) == saved
    assert m.usb_count == 2
    result = host.wait()
    assert (result.status, result.v0, result.v1, result.f0) == (
        (1, 0, 0, 0) if bad_operation else (0, 123, 456, 789)
    )
    commits = [
        i
        for i, (address, _) in enumerate(m.memory.writes)
        if address == m.config.mailbox + 4
    ]
    assert len(commits) == 1
    assert m.memory.writes[commits[0] - 1] == ("sync", 0)


@pytest.mark.parametrize("busy,fault", [(1, 0), (0, 3), (1, 3)])
def test_frame_callback_skipped_when_busy_or_faulted(busy, fault):
    m = Machine(frame_configuration())
    m.memory.words[m.config.mailbox + 8] = busy
    m.memory.words[m.config.mailbox + 84] = fault
    saved = (dict(m.gpr), list(m.fpr), dict(m.special))
    m.run()  # No callbacks registered: any invocation is a failure.
    assert (m.gpr, m.fpr, m.special) == saved
    assert m.usb_count == 1
    assert m.memory.read32(m.config.mailbox + 8) == busy
    assert m.memory.read32(m.config.mailbox + 84) == fault


def test_bad_sequence_does_not_invoke_frame_callback():
    m = Machine(frame_configuration())
    m.memory.words[m.config.mailbox] = 3
    m.run()
    assert m.memory.read32(m.config.mailbox + 84) == 3
    assert m.usb_count == 1


@pytest.mark.parametrize("with_command", [False, True])
def test_frame_nonlocal_exit_latches_busy_without_committing(with_command):
    m = Machine(frame_configuration())
    host = Host(m.memory, m.config.mailbox, table_size=2)
    events = []
    if with_command:
        host.submit(Call(0))
    m.callbacks[0x110000] = lambda _: events.append("command")

    def frame(machine):
        events.append("frame")
        raise NonlocalExit()

    m.callbacks[0x130000] = frame
    with pytest.raises(NonlocalExit):
        m.run()
    assert m.usb_count == 0
    assert m.low("$sp") == sum(m.config.target_stack) - 80
    assert m.memory.read32(m.config.mailbox + 8) == 1
    assert m.memory.read32(m.config.mailbox + 4) == 0
    m.run()
    assert m.usb_count == 1
    assert events == (["command", "frame"] if with_command else ["frame"])
    if with_command:
        with pytest.raises(Pending):
            host.wait(timeout=0.001)


def test_frame_callback_requires_private_stack_and_approved_target():
    with pytest.raises(ValueError, match="requires target_stack"):
        configuration(frame_callback=Target(0x130000, 0x610000))
    for callback in (0x130000, (0x130000, 0x610000), {"address": 0x130000}):
        with pytest.raises(ValueError, match="approved Target"):
            frame_configuration(frame_callback=callback)
    with pytest.raises(ValueError, match="whitelist"):
        frame_configuration(frame_callback=Target(0x300000, 0x610000))
    for address, gp in (
        (0x130001, 0x610000),
        (0x130000, 0x610001),
        (0x130000, 0x2000000),
        (0xC0130000, 0x610000),
    ):
        with pytest.raises(ValueError):
            frame_configuration(frame_callback=Target(address, gp))
    config = frame_configuration(frame_callback=Target(0x80130000, 0xA0610000))
    assert config.frame_callback == Target(0x130000, 0x610000)
    assert config.frame_callback not in config.targets  # Not a host command entry.


def test_nonreturning_command_cannot_start_frame_callback():
    m = Machine(frame_configuration())
    host = Host(m.memory, m.config.mailbox, table_size=2)
    host.submit(Call(0))

    def command(machine):
        machine.run()  # Reentry from a host target must not run frame work either.
        raise NonlocalExit()

    m.callbacks[0x110000] = command
    with pytest.raises(NonlocalExit):
        m.run()  # No frame callback registered: any call is a test failure.
    assert m.usb_count == 1
    assert m.memory.read32(m.config.mailbox + 8) == 1
    assert m.memory.read32(m.config.mailbox + 4) == 0
    with pytest.raises(Pending):
        host.wait(timeout=0.001)


def test_last_nonzero_sequence_completes_but_cannot_wrap():
    m = Machine()
    for offset in (0, 4, 12):
        m.memory.words[m.config.mailbox + offset] = 0xFFFFFFFE
    host = Host(m.memory, m.config.mailbox, table_size=2)
    m.callbacks[0x110000] = lambda _: None
    assert host.submit(Call(0)) == 0xFFFFFFFF
    m.run()
    assert host.wait().sequence == 0xFFFFFFFF
    with pytest.raises(ProtocolError, match="exhausted"):
        host.submit(Call(0))


@pytest.mark.parametrize("sequence,last", [(0, 0xFFFFFFFF), (1, 2), (3, 1)])
def test_bad_sequences_fail_closed(sequence, last):
    m = Machine()
    m.memory.words[m.config.mailbox] = sequence
    m.memory.words[m.config.mailbox + 12] = last
    m.run()
    assert m.usb_count == 1
    assert m.memory.read32(m.config.mailbox + 84) == 3
    assert m.memory.read32(m.config.mailbox + 4) == 0


@pytest.mark.parametrize("offset,value,status", [(16, 2, 2), (20, 2, 1)])
def test_invalid_command_gets_committed_error(offset, value, status):
    m = Machine()
    host = Host(m.memory, m.config.mailbox, table_size=2)
    host.submit(Call(0))
    m.memory.words[m.config.mailbox + offset] = value
    m.run()
    assert host.wait().status == status
    assert m.usb_count == 1


@pytest.mark.parametrize("address", [0x110002, 0x300000, 0x80110000, 0xFFFFFFFF])
def test_corrupt_table_fails_closed(address):
    m = Machine()
    host = Host(m.memory, m.config.mailbox, table_size=2)
    host.submit(Call(0))
    m.memory.words[m.table_address] = address
    m.run()
    assert host.wait().status == 2
