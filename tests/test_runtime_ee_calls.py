"""Synthetic R5900 instruction execution, with optional real EE assembly.

The small encoder covers only this authored veneer. The independent real-tool
comparison also checks its instruction encodings, including the 128-bit POR.
No original executable or capture is needed.
"""

import re
import shutil
import struct

import pytest

from local_config import ee_tool
from runtime import ee_calls
from test_native_lifecycle_hooks import MASK64, Machine, config


TARGET = 0x00512344
GP = 0x0067FEDC
CODE = 0x01400000
ARGS = tuple(range(4, 12))


def assemble(text):
    """Encode the emitted subset to words before executing (not text evaluation)."""
    words = []
    names = Machine(config())
    for line in text.splitlines():
        if not line or line.startswith(".") or line.endswith(":"):
            continue
        op, *tail = line.split(maxsplit=1)
        a = tail[0].split(", ") if tail else []
        reg = names.idx
        if op == "nop":
            word = 0
        elif op in ("por", "and"):
            word = reg(a[1]) << 21 | reg(a[2]) << 16 | reg(a[0]) << 11
            word |= (0x1C << 26 | 0x12 << 6 | 0x29) if op == "por" else 0x24
        elif op in ("addiu", "ori"):
            word = (
                (9 if op == "addiu" else 13) << 26
                | reg(a[1]) << 21
                | reg(a[0]) << 16
                | (int(a[2]) & 0xFFFF)
            )
        elif op == "lui":
            word = 15 << 26 | reg(a[0]) << 16 | int(a[1])
        elif op in ("sq", "lq"):
            offset, base = re.fullmatch(r"(\d+)\((\$\w+)\)", a[1]).groups()
            word = (
                (31 if op == "sq" else 30) << 26
                | reg(base) << 21
                | reg(a[0]) << 16
                | int(offset)
            )
        elif op == "jalr":
            word = reg(a[1]) << 21 | reg(a[0]) << 11 | 9
        elif op == "jr":
            word = reg(a[0]) << 21 | 8
        else:
            raise AssertionError(line)
        words.append(word)
    return struct.pack(f"<{len(words)}I", *words)


class VeneerMachine(Machine):
    """Reuse lifecycle register/memory model; decode this veneer locally."""

    def __init__(self, alignment, *, nested=False):
        super().__init__(config())
        self.r[29] += alignment
        self.entry = self.snapshot()
        self.code = assemble(ee_calls.render("native_call", TARGET, GP))
        self.calls = []
        self.writes = []
        self.nested = nested

    def run_words(self, code=None):
        words = struct.unpack(f"<{len(code or self.code) // 4}I", code or self.code)
        pc = 0
        for _ in range(100):
            word = words[pc]
            pc += 1
            op, rs, rt, rd = (
                word >> 26,
                word >> 21 & 31,
                word >> 16 & 31,
                word >> 11 & 31,
            )
            imm = word & 0xFFFF
            signed = (imm ^ 0x8000) - 0x8000
            if not word:
                continue
            if op == 0x1C:
                assert word & 0x7FF == 0x12 << 6 | 0x29
                self.r[rd] = self.r[rs] | self.r[rt]
            elif op == 0 and word & 63 == 0x24:
                self.set(str(rd), self.r[rs] & self.r[rt])
            elif op in (9, 13, 15):
                value = (
                    self.r[rs] + signed
                    if op == 9
                    else self.r[rs] | imm
                    if op == 13
                    else imm << 16
                )
                self.set(str(rt), value)
            elif op in (30, 31):
                address = (self.r[rs] & MASK64) + signed
                assert address % 16 == 0, "unaligned quadword access"
                if op == 31:
                    self.writes.append(address)
                    self.mem[address] = self.r[rt]
                else:
                    self.reads.append(address)
                    self.r[rt] = self.mem[address]
            elif op == 0 and word & 63 in (8, 9):
                assert words[pc] == 0, "explicit NOP delay required"
                pc += 1
                if word & 63 == 8:
                    return
                assert self.r[rs] & MASK64 == TARGET
                self.set(str(rd), CODE + pc * 4)
                self.native()
            else:
                raise AssertionError(hex(word))
        raise AssertionError("veneer did not return")

    def native(self):
        expected = self.snapshot()
        sp = self.low("sp")
        assert sp % 16 == 0
        assert self.low("gp") == GP
        self.calls.append(expected)
        # A stock callee may overwrite all eight home slots, not just arg 1.
        for offset in range(0, 64, 16):
            self.mem[sp + offset] = (1 << 128) - 1
        if self.nested and len(self.calls) == 1:
            # Real EABI C frames need only eight-byte alignment (e.g. 24 bytes).
            self.set("sp", sp - 24)
            callback = self.snapshot()
            outer_saved = {a: self.mem[a] for a in (sp + 64, sp + 80, sp + 96)}
            self.run_words()
            assert [self.calls[1][0][i] for i in ARGS] == [callback[0][i] for i in ARGS]
            assert self.calls[1][1] == callback[1]
            assert self.r[29] == callback[0][29]
            assert self.r[28] == callback[0][28]
            assert self.r[31] == callback[0][31]
            assert {a: self.mem[a] for a in outer_saved} == outer_saved
            self.r[29], self.r[31] = expected[0][29], expected[0][31]
        self.clobber(300 + len(self.calls))
        self.r[2] = (0xDEADBEEF << 96) | 0xF0000001
        self.r[3] = (0xBAADF00D << 96) | 0xE0000002
        self.f[0] = 0x41234567
        self.post = self.snapshot()


@pytest.mark.parametrize("alignment", [0, 8])
@pytest.mark.parametrize("nested", [False, True])
def test_full_width_arguments_results_and_per_caller_frames(alignment, nested):
    m = VeneerMachine(alignment, nested=nested)
    before = m.entry
    m.run_words()
    assert len(m.calls) == (2 if nested else 1)
    assert [m.calls[0][0][i] for i in ARGS] == [before[0][i] for i in ARGS]
    assert m.calls[0][1] == before[1]  # all FPU arguments untouched
    for reg in (28, 29, 31):
        assert m.r[reg] == before[0][reg]  # includes nonzero upper 64 bits
    expected = m.post[0].copy()
    for reg in (28, 29, 31):
        expected[reg] = before[0][reg]
    assert m.snapshot() == (expected, *m.post[1:])
    frame = m.calls[0][0][29] & MASK64
    assert (before[0][29] & MASK64) - frame == 112 + alignment
    assert m.writes[:3] == [frame + 64, frame + 80, frame + 96]
    assert all(address % 16 == 0 for address in m.writes + m.reads)


@pytest.mark.parametrize("label", ["", "a:b", "foo\njal evil", ".foo", "1foo", None])
def test_reject_label(label):
    with pytest.raises(ValueError):
        ee_calls.render(label, TARGET, GP)


@pytest.mark.parametrize("address", [None, True, 0, -4, 0x02000000, 0x80001000, "1234"])
@pytest.mark.parametrize("field", ["target", "gp"])
def test_reject_nonphysical_addresses(address, field):
    values = {"target": TARGET, "gp": GP}
    values[field] = address
    with pytest.raises(ValueError):
        ee_calls.render("call", **values)


@pytest.mark.parametrize("target", [1, 2, TARGET + 1, TARGET + 2])
def test_reject_unaligned_target(target):
    with pytest.raises(ValueError):
        ee_calls.render("call", target, GP)


@pytest.mark.parametrize("address", [0, CODE + 4, 0x02000000, True])
def test_reject_invalid_placement_before_tool_invocation(address):
    with pytest.raises(ValueError):
        ee_calls.build("call", TARGET, GP, address, assembler="not-a-tool")


def test_source_contract():
    text = ee_calls.render("call", TARGET, GP)
    assert text.count("jalr ") == 1
    assert "por $t8, $sp, $zero" in text
    assert "ninth" in ee_calls.__doc__
    assert "not trapped" in ee_calls.__doc__
    assert "120 bytes" in ee_calls.__doc__


def test_optional_real_ee_assembly():
    assembler = ee_tool("as")
    if not shutil.which(str(assembler)):
        pytest.skip("optional EE assembler unavailable")
    result = ee_calls.build("native_call", TARGET, GP, CODE, assembler=assembler)
    assert result.exports["native_call"] == CODE
    text = next(p.data for p in result.payloads if p.section == ".text")
    expected = assemble(ee_calls.render("native_call", TARGET, GP))
    assert text[: len(expected)] == expected
    for alignment in (0, 8):
        machine = VeneerMachine(alignment)
        machine.run_words(text[: len(expected)])
        assert machine.r[29] == machine.entry[0][29]
