"""Offline general sheet-worker gate. No transport or implicit state initialization."""

import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from pathlib import Path

from injection.barriers import _load, _restore, _save
from runtime.elf import link_object
from runtime.patches import WordPatch


class Phase(IntEnum):
    IDLE = 0
    WAIT = 1
    RELEASING = 2


class Fault(IntFlag):
    BAD_STATE = 1
    NESTED = 2
    OVERFLOW = 4
    WRONG_PERMIT = 8
    BAD_REQUEST = 16


FIELDS = (
    "magic",
    "version",
    "generation",
    "sequence",
    "phase",
    "request",
    "sheet",
    "segment",
    "op",
    "permit_sequence",
    "permit_generation",
    "complete_sequence",
    "complete_generation",
    "fault",
    "ready",
)
OFF = {name: i * 4 for i, name in enumerate(FIELDS)}
MAGIC, VERSION, STATE_SIZE, CODE_SIZE = 0x52475348, 1, 0x40, 0x6000
ENTRY, COMPLETE, SHEET_WAIT = 0xE3350, 0xE37A0, 0xE3978


def initial_state(*, generation=1):
    if type(generation) is not int or not 0 < generation <= 0xFFFFFFFF:
        raise ValueError("nonzero uint32 generation required")
    values = dict.fromkeys(FIELDS, 0)
    values.update(magic=MAGIC, version=VERSION, generation=generation)
    return struct.pack("<16I", *(values[n] for n in FIELDS), 0)


@dataclass(frozen=True)
class Config:
    m: int
    code: int
    state: int
    expected_wait_sema: int
    manager_text_size: int = 0x120000

    def __post_init__(self):
        for a in (self.m, self.code, self.state, self.expected_wait_sema):
            if type(a) is not int or not 0x80000 <= a < 0x2000000 or a % 4:
                raise ValueError("aligned physical EE address required")
        if self.code % 16 or self.state % 16:
            raise ValueError("owned extents must be 16-byte aligned")
        if (
            type(self.manager_text_size) is not int
            or self.manager_text_size < SHEET_WAIT + 32
        ):
            raise ValueError("manager text extent must cover guarded code")
        spans = [
            (self.code, self.code + CODE_SIZE),
            (self.state, self.state + STATE_SIZE),
            (self.m, self.m + self.manager_text_size),
        ]
        if any(b > 0x2000000 for _, b in spans) or any(
            a < d and c < b for i, (a, b) in enumerate(spans) for c, d in spans[i + 1 :]
        ):
            raise ValueError("owned/manager extents overlap or overflow")
        if any(a <= self.expected_wait_sema < b for a, b in spans[:2]):
            raise ValueError("WaitSema overlaps owned extent")


def guard_expectations(c):
    return {
        c.m + offset: pair
        for offset, pair in {
            0xE3338: (0x50400005, 0xFFFFFFFF),
            0xE333C: (0x8E450000, 0xFFFFFFFF),
            0xE3344: (0x10000114, 0xFFFFFFFF),
            ENTRY: (0x2CA2000D, 0xFFFFFFFF),
            ENTRY + 4: (0x1040010C, 0xFFFFFFFF),
            ENTRY + 8: (0x3C030000, 0xFFFF0000),
            ENTRY + 12: (0x3C030000, 0xFFFF0000),
            COMPLETE: (0x0C000000 | (c.expected_wait_sema >> 2), 0xFFFFFFFF),
            COMPLETE + 4: (0x8E840000, 0xFFFF0000),
            SHEET_WAIT: (0x27BDFFF0, 0xFFFFFFFF),
            SHEET_WAIT + 4: (0x3C030000, 0xFFFF0000),
            SHEET_WAIT + 8: (0xFFBF0000, 0xFFFFFFFF),
        }.items()
    }


def render(c, words):
    for a, (value, mask) in guard_expectations(c).items():
        w = words.get(a)
        if type(w) is not int or not 0 <= w <= 0xFFFFFFFF or w & mask != value:
            raise ValueError(f"unsupported instruction at {a:#x}")
    out = [".set noreorder", ".set noat", '.section .text,"ax",@progbits', ".balign 16"]

    def emit(*lines):
        out.extend(lines)

    def branch(line):
        emit(line, "nop")

    def state():
        emit(*_load("$t0", c.state))

    def lw(reg, name):
        emit(f"lw {reg}, {OFF[name]}($t0)")

    def sw(reg, name):
        emit(f"sw {reg}, {OFF[name]}($t0)")

    def validate():
        state()
        for field, value in (("magic", MAGIC), ("version", VERSION)):
            lw("$t1", field)
            emit(*_load("$t2", value))
            branch("bne $t1, $t2, bad_state")
        lw("$t1", "fault")
        branch("bne $t1, $zero, blocked")

    emit(".globl resource_gate_entry", "resource_gate_entry:", *_save())
    # Classify using the original low word, without dereferencing other op requests.
    emit("lw $t1, 80($sp)")
    for op in (1, 3, 5, 6):
        emit(f"addiu $t2, $zero, {op}")
        branch("beq $t1, $t2, destructive")
    branch("b resume")
    emit("destructive:")
    validate()
    lw("$t1", "phase")
    branch("bne $t1, $zero, nested")
    lw("$t1", "generation")
    branch("beq $t1, $zero, bad_state")
    lw("$t1", "sequence")
    emit("addiu $t2, $zero, -1")
    branch("beq $t1, $t2, overflow")
    for field in ("permit_sequence", "permit_generation"):
        lw("$t2", field)
        branch("bne $t2, $zero, wrong_permit")
    # Only request offsets 0, 8, 12 are read. Validate before dereferencing.
    emit("lw $t3, 288($sp)", *_load("$t2", 0x80000), "sltu $t4, $t3, $t2")
    branch("bne $t4, $zero, bad_request")
    emit(*_load("$t2", 0x1FFFFF1), "sltu $t4, $t3, $t2")
    branch("beq $t4, $zero, bad_request")
    emit("andi $t4, $t3, 3")
    branch("bne $t4, $zero, bad_request")
    emit("lw $t4, 0($t3)", "lw $t2, 80($sp)")
    branch("bne $t4, $t2, bad_request")
    emit("addiu $t1, $t1, 1")
    sw("$t1", "sequence")
    sw("$t3", "request")
    sw("$t4", "op")
    for offset, field in ((8, "sheet"), (12, "segment")):
        emit(f"lw $t4, {offset}($t3)")
        sw("$t4", field)
    for field, slot in (("sequence", 680), ("generation", 684), ("request", 688)):
        lw("$t1", field)
        emit(f"sw $t1, {slot}($sp)")
    sw("$zero", "ready")
    emit("sync", "addiu $t1, $zero, 1")
    sw("$t1", "phase")
    emit("sync", "watch:")
    validate()
    lw("$t1", "phase")
    emit("addiu $t2, $zero, 1")
    branch("bne $t1, $t2, bad_state")
    for field, slot in (("sequence", 680), ("generation", 684), ("request", 688)):
        lw("$t1", field)
        emit(f"lw $t2, {slot}($sp)")
        branch("bne $t1, $t2, bad_state")
    lw("$t1", "permit_sequence")
    lw("$t2", "permit_generation")
    emit("or $t3, $t1, $t2")
    branch("beq $t3, $zero, sleep")
    lw("$t3", "sequence")
    branch("bne $t1, $t3, wrong_permit")
    lw("$t3", "generation")
    branch("bne $t2, $t3, wrong_permit")
    emit("addiu $t1, $zero, 2", "sync")
    sw("$t1", "phase")
    emit("sync")
    branch("b resume")
    emit("sleep:", "addiu $sp, $sp, -32")
    branch(f"jal 0x{c.m + SHEET_WAIT:x}")
    emit("addiu $sp, $sp, 32")
    branch("b watch")
    for label, flag in (
        ("bad_state", Fault.BAD_STATE),
        ("nested", Fault.NESTED),
        ("overflow", Fault.OVERFLOW),
        ("wrong_permit", Fault.WRONG_PERMIT),
        ("bad_request", Fault.BAD_REQUEST),
    ):
        emit(label + ":")
        state()
        lw("$t1", "fault")
        emit(f"ori $t1, $t1, {int(flag)}")
        sw("$t1", "fault")
        sw("$zero", "ready")
        emit("sync")
        branch("b blocked")
    emit("blocked:", "addiu $sp, $sp, -32")
    branch(f"jal 0x{c.m + SHEET_WAIT:x}")
    emit("addiu $sp, $sp, 32")
    branch("b blocked")
    emit("resume:", *_restore(), f".word 0x{words[c.m + ENTRY]:08x}")
    branch("beq $v0, $zero, out_of_range")
    emit(f".word 0x{words[c.m + ENTRY + 8]:08x}")
    branch(f"j 0x{c.m + ENTRY + 12:x}")
    emit("out_of_range:", f".word 0x{words[c.m + ENTRY + 8]:08x}")
    branch(f"j 0x{c.m + 0xE3788:x}")
    emit(".globl resource_gate_complete", "resource_gate_complete:", *_save())
    state()
    lw("$t1", "phase")
    emit("addiu $t2, $zero, 2")
    branch("bne $t1, $t2, completion_tail")
    lw("$t1", "request")
    emit("lw $t2, 288($sp)")
    branch("bne $t1, $t2, completion_tail")
    validate()
    for current, permit in (
        ("sequence", "permit_sequence"),
        ("generation", "permit_generation"),
    ):
        lw("$t1", current)
        lw("$t2", permit)
        branch("bne $t1, $t2, bad_state")
    for current in ("sequence", "generation"):
        lw("$t1", current)
        sw("$t1", "complete_" + current)
    sw("$zero", "permit_sequence")
    sw("$zero", "permit_generation")
    emit("sync")
    sw("$zero", "phase")
    emit("sync", "completion_tail:", *_restore())
    # Tail call preserves original SP, arguments, RA and the callee's post-call ABI.
    branch(f"j 0x{c.expected_wait_sema:x}")
    return "\n".join(out) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="resource-gate-") as folder:
        source, obj = Path(folder) / "gate.s", Path(folder) / "gate.o"
        source.write_text(assembly)
        subprocess.run(
            [
                str(assembler),
                "-EL",
                "-march=r5900",
                "-mabi=eabi",
                "-o",
                str(obj),
                str(source),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(objcopy),
                "--remove-section=.MIPS.abiflags",
                "--remove-section=.reginfo",
                str(obj),
            ],
            check=True,
            capture_output=True,
        )
        linked = link_object(
            obj.read_bytes(),
            {
                ".text": c.code,
                ".data": c.code + CODE_SIZE - 32,
                ".bss": c.code + CODE_SIZE - 16,
            },
        )
    if any(
        p.address < c.code or p.address + len(p.data) > c.code + CODE_SIZE
        for p in linked.payloads
    ):
        raise ValueError("code exceeds owned extent")
    patches = [
        WordPatch(
            c.m + ENTRY,
            words[c.m + ENTRY],
            0x08000000 | (linked.exports["resource_gate_entry"] >> 2),
        ),
        WordPatch(c.m + ENTRY + 4, words[c.m + ENTRY + 4], 0),
        WordPatch(
            c.m + COMPLETE,
            words[c.m + COMPLETE],
            0x0C000000 | (linked.exports["resource_gate_complete"] >> 2),
        ),
    ]
    return Build(assembly, linked, tuple(patches))
