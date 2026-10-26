"""Offline source-instruction execution and real EE assembly/link checks."""

import re
import shutil
from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_native_lifecycle_hooks as model

from bootstrap import allocator as a
from local_config import ee_tool, original_file


def spec():
    return a.AllocationSpec(
        g=0x1300038,
        k=0x180038,
        m=0x1100038,
        cave=0x1300038 + a.CAVE_OFFSET,
        original_cave=bytes(a.CAVE_SIZE),
        root_heap=0x1E0C88,
        requested_size=0x10000,
        allocator=0x180038 + a.ALLOC_OFFSET,
        allocator_gp=0x141D70,
        unused_attestation="debug inputs disabled and callers excluded",
        quiescence_attestation="exclusive paused safe point; no cave continuations",
        provenance_attestation="original image and relocated operands verified",
        stack_attestation="incoming frame headroom independently qualified",
    )


class Machine(model.Machine):
    def __init__(self, c, result, status=0):
        super().__init__(SimpleNamespace(canonical_group=0x830000))
        self.spec, self.result = c, result
        for offset in range(0, 16, 4):
            self.mem[c.state + offset] = status if offset == 0 else 0
        self.initial = self.snapshot()
        self.allocations = 0

    def run(self):
        lines, labels = [], {}
        for line in a.render(self.spec).splitlines():
            if line.endswith(":"):
                labels[line[:-1]] = len(lines)
            elif not line.startswith("."):
                lines.append(line)
        pc = 0
        for _ in range(1000):
            op, *tail = lines[pc].split(maxsplit=1)
            pc += 1
            args = tail[0].split(", ") if tail else []
            if op in ("nop", "sync"):
                continue
            if op in ("beq", "bne", "b", "jal", "j"):
                assert lines[pc] == "nop"
                pc += 1
                if op == "j":
                    assert args == ["original_usb"]
                    assert self.snapshot() == self.initial
                    self.events.append("usb")
                    return
                if op == "jal":
                    assert args == ["original_allocator"]
                    self.allocations += 1
                    assert self.mem[self.spec.state] == 1
                    assert tuple(self.low(r) for r in ("a0", "a1", "a2", "gp")) == (
                        self.spec.root_heap,
                        self.spec.requested_size,
                        16,
                        self.spec.allocator_gp,
                    )
                    assert (
                        self.low("sp")
                        == (self.initial[0][29] & model.MASK64) - a.FRAME_SIZE
                    )
                    # Native allocator follows EABI. Caller-saved state is trash.
                    preserved = {i: self.r[i] for i in range(16, 24)}
                    preserved[30] = self.r[30]
                    self.clobber(99)
                    for i, value in preserved.items():
                        self.r[i] = value
                    self.set("v0", self.result)
                elif op == "b":
                    pc = labels[args[0]]
                elif (self.low(args[0]) == self.low(args[1])) == (op == "beq"):
                    pc = labels[args[2]]
                continue
            if op in ("sq", "lq", "sw", "lw", "swc1", "lwc1"):
                match = re.fullmatch(r"(-?\d+)\((\$\w+)\)", args[1])
                address = self.low(match[2]) + int(match[1])
                if op in ("sq", "sw", "swc1"):
                    value = (
                        self.f[int(args[0][2:])]
                        if op == "swc1"
                        else self.r[self.idx(args[0])]
                    )
                    self.mem[address] = value if op == "sq" else value & 0xFFFFFFFF
                else:
                    value = self.mem[address]
                    if op == "lq":
                        self.r[self.idx(args[0])] = value
                    elif op == "lwc1":
                        self.f[int(args[0][2:])] = value
                    else:
                        self.set(
                            args[0], ((value & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000
                        )
            elif op in ("lui", "ori", "andi", "addiu", "addu", "sltu"):
                if op == "lui":
                    value = int(args[1]) << 16
                elif op == "ori":
                    value = self.low(args[1]) | int(args[2])
                elif op == "andi":
                    value = self.low(args[1]) & int(args[2])
                elif op == "addiu":
                    value = (self.low(args[1]) + int(args[2])) & 0xFFFFFFFF
                    value = (value ^ 0x80000000) - 0x80000000
                elif op == "addu":
                    value = (self.low(args[1]) + self.low(args[2])) & 0xFFFFFFFF
                else:
                    value = int(self.low(args[1]) < self.low(args[2]))
                self.set(args[0], value)
            elif op in ("pmfhi", "pmflo"):
                self.r[self.idx(args[0])] = self.hi if op == "pmfhi" else self.lo
            elif op in ("pmthi", "pmtlo"):
                setattr(
                    self, "hi" if op == "pmthi" else "lo", self.r[self.idx(args[0])]
                )
            elif op in ("mfsa", "cfc1"):
                self.set(args[0], self.sa if op == "mfsa" else self.fcsr)
            elif op in ("mtsa", "ctc1"):
                setattr(
                    self,
                    "sa" if op == "mtsa" else "fcsr",
                    self.low(args[0]) & 0xFFFFFFFF,
                )
            else:
                raise AssertionError(op)
        raise AssertionError("did not tail-call USB")


@pytest.mark.parametrize(
    "result,status,error",
    [
        (0x1800000, 2, 0),
        (0, 3, 1),
        (0x1800001, 3, 2),
        (0x7FFF0, 3, 2),
        (0x2000000, 3, 2),
        (0x1FF0010, 3, 2),
        (0xFFFFFFFF, 3, 2),
        (0x1FF0000, 2, 0),
        (0x1300000, 3, 2),
    ],
)
def test_once_results_and_full_state(result, status, error):
    m = Machine(spec(), result)
    m.run()
    assert m.mem[m.spec.state] == status
    assert m.mem[m.spec.state + 4] == (result if status == 2 else 0)
    assert m.mem[m.spec.state + 8] == result
    assert m.mem[m.spec.state + 12] == error
    m.run()
    assert m.allocations == 1
    assert m.events == ["usb", "usb"]


@pytest.mark.parametrize("status", [1, 2, 3, 99])
def test_existing_state_never_reallocates(status):
    m = Machine(spec(), 0x1800000, status)
    m.run()
    assert m.allocations == 0
    assert m.mem[m.spec.state] == status


@pytest.mark.parametrize(
    "changes",
    [
        {"unused_attestation": ""},
        {"quiescence_attestation": ""},
        {"provenance_attestation": ""},
        {"stack_attestation": ""},
        {"cave": 0x1600000},
        {"requested_size": 0xFFFF},
        {"requested_size": 0x200001},
        {"requested_size": True},
        {"alignment": 32},
        {"allocator": 0x180000},
        {"original_cave": b""},
        {"root_heap": 0xFFFFFFFF},
    ],
)
def test_reject_invalid_spec(changes):
    with pytest.raises(ValueError):
        replace(spec(), **changes)


ORIGINAL = original_file("GAMECORE.XFF")


def test_original_module_offsets_use_text_relative_coordinates():
    if not ORIGINAL.is_file():
        pytest.skip("local original module unavailable")
    core = a.parse(ORIGINAL.read_bytes())
    references = [
        r
        for table in core.reltables
        if table.target == core.index_of(".text")
        for r in table.entries
        if r[0] == a.CALL_OFFSET
    ]
    assert len(references) == 1
    assert core.symbol_name(references[0][1] >> 8) == "usbdevFrameInit"
    manager_path = ORIGINAL.with_name("MANAGER.XFF")
    if not manager_path.is_file():
        pytest.skip("local original manager unavailable")
    manager = a.parse(manager_path.read_bytes())
    values = [
        manager.symbol(i)[1]
        for i in range(manager.num_symbols)
        if manager.symbol_name(i) == "usbdevFrameInit"
    ]
    assert values == [a.USB_OFFSET]
ASSEMBLER = ee_tool("as")


def original_spec():
    if not ORIGINAL.is_file():
        pytest.skip("private original not available")
    from runtime.xff import parse

    raw = ORIGINAL.read_bytes()
    module = parse(raw)
    # Unrelocated fixtures are acceptable ONLY to the offline guard test. They
    # are not a certified loaded image and must never authorize installation.
    cave = module.sections[module.index_of(".text")].data[
        a.CAVE_OFFSET : a.CAVE_OFFSET + a.CAVE_SIZE
    ]
    return replace(spec(), original_cave=cave), raw


def test_original_provenance():
    c, raw = original_spec()
    a.validate_original(c, raw)
    with pytest.raises(ValueError):
        a.validate_original(c, raw[:-1])
    changed = bytearray(c.original_cave)
    changed[0] ^= 1
    with pytest.raises(ValueError):
        a.validate_original(replace(c, original_cave=bytes(changed)), raw)


def test_real_ee_build_and_guards():
    c, raw = original_spec()
    tool = (
        str(ASSEMBLER)
        if ASSEMBLER.exists()
        else shutil.which("mips64r5900el-ps2-elf-as")
    )
    if not tool:
        pytest.skip("EE assembler unavailable")
    observations = dict(a.guard_expectations(c))
    plan = a.build(c, raw, lambda address, size: observations[address], assembler=tool)
    assert len(plan.code) <= c.state - c.cave
    assert plan.state_bytes == bytes(16)
    assert plan.patches[0].address == c.g + a.CALL_OFFSET
    assert plan.restore_call.expected == plan.patches[0].replacement
    assert plan.restore_call.replacement == a._jal(c.m + a.USB_OFFSET)
    assert plan.original_cave == c.original_cave
    for address in observations:
        bad = dict(observations)
        bad[address] = b"\xff" * len(bad[address])
        with pytest.raises(ValueError, match="guard mismatch"):
            a.build(
                c,
                raw,
                lambda address, size, values=bad: values[address],
                assembler=tool,
            )
