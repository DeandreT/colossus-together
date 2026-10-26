import dataclasses

import pytest
from test_commands_dispatch import Memory, configuration

from commands.generator import Target, guards, physical, render
from commands.protocol import MAX_SEQUENCE, Call, Host, Pending, ProtocolError


def test_publication_is_last_and_host_never_touches_object_memory():
    mem = Memory()
    host = Host(mem, 0x1500000, table_size=2)
    assert host.submit(Call(1, tuple(range(8)), (9, 10, 11))) == 1
    assert mem.writes == [
        (0x1500010, 1),
        (0x1500014, 1),
        *((0x1500018 + i * 4, i) for i in range(8)),
        *((0x1500038 + i * 4, i + 9) for i in range(3)),
        (0x1500000, 1),
    ]
    with pytest.raises(Pending):
        host.wait(timeout=0.001)
    writes = list(mem.writes)
    with pytest.raises(ProtocolError):
        host.submit(Call(0))
    assert mem.writes == writes
    mem.words.update({0x1500004: 1, 0x150000C: 1, 0x1500048: 123})
    assert host.wait(timeout=0.001).v0 == 123
    assert host.submit(Call(0)) == 2


def test_partial_or_uncertain_write_cannot_be_retried():
    class Broken(Memory):
        def write32(self, address, value):
            super().write32(address, value)
            raise OSError("unknown completion")

    memory = Broken()
    host = Host(memory, 0x1500000, table_size=2)
    with pytest.raises(OSError):
        host.submit(Call(0))
    with pytest.raises(ProtocolError):
        host.submit(Call(0))
    assert len(memory.writes) == 1
    assert host.pending_sequence == 1


def test_overflow_requires_new_installation():
    mem = Memory()
    for offset in (0, 4, 12):
        mem.words[0x1500000 + offset] = MAX_SEQUENCE
    host = Host(mem, 0x1500000, table_size=1)
    with pytest.raises(ProtocolError, match="exhausted"):
        host.submit(Call(0))
    assert not mem.writes


@pytest.mark.parametrize("offset,value", [(0, 1), (4, 1), (8, 1), (12, 1), (84, 3)])
def test_adopt_only_idle_mailbox(offset, value):
    mem = Memory()
    mem.words[0x1500000 + offset] = value
    with pytest.raises(ProtocolError):
        Host(mem, 0x1500000, table_size=1)


@pytest.mark.parametrize("value", [-1, 0x100000000, True, 1.0])
def test_argument_validation_precedes_publication(value):
    with pytest.raises(ValueError):
        Call(0, (value,) * 8)
    with pytest.raises(ValueError):
        Call(value)


def test_no_stack_arguments_or_arbitrary_function_address():
    with pytest.raises(ValueError):
        Call(0, (0,) * 9)
    mem = Memory()
    host = Host(mem, 0x1500000, table_size=1)
    with pytest.raises(ValueError):
        host.submit(Call(0x110000))
    assert not mem.writes


def test_exact_entry_and_call_guards_required():
    config = configuration()
    for address in guards(config):
        observed = guards(config)
        observed[address] ^= 1
        with pytest.raises(ValueError, match="guard failed"):
            render(config, observed)
    with pytest.raises(ValueError):
        render(config, {})
    with pytest.raises(ValueError):
        configuration(usb_entry=(0, 0))
    with pytest.raises(ValueError):
        configuration(delay_word=1)


def test_whitelist_alias_alignment_and_immutable_table():
    assert physical(0x80110000) == 0x110000
    assert physical(0xA0110000) == 0x110000
    assert Target(0x80110000, 0xA0600000) == Target(0x110000, 0x600000)
    for value in (0xC0110000, 0x20110000, 0x110002, 0x2000000, -1):
        with pytest.raises(ValueError):
            physical(value)
    for address in (0x200000, 0x300000):
        with pytest.raises(ValueError):
            configuration(targets=(Target(address, 0x600000),))
    with pytest.raises(ValueError):
        configuration(code=0x110000)
    with pytest.raises(ValueError):
        configuration(mailbox=0x1400000)
    config = configuration()
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.targets = ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.targets[0].address = 0x130000


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_timeout_must_be_bounded(timeout):
    host = Host(Memory(), 0x1500000, table_size=1)
    host.submit(Call(0))
    with pytest.raises(ValueError):
        host.wait(timeout=timeout)
