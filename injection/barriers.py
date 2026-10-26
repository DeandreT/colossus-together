"""Offline NTSC-U sheet-worker barriers; no emulator I/O or telemetry ring.

g/m are loaded listing origins, as in injection.generator. See BARRIERS.md for
the paused-host handshake, hook scope, and machine-state preservation contract.
"""

import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch


class Phase(IntEnum):
    IDLE = 0
    WAIT = 1
    RELEASING = 2


class Fault(IntFlag):
    NESTED = 1
    OVERFLOW = 2
    UNKNOWN_PERMIT = 4
    ABORT = 8
    TIMEOUT = 16
    UNACKNOWLEDGED = 32
    BAD_STATE = 64
    UNEXPECTED_CLEANUP = 128


FIELDS = (
    "magic",
    "version",
    "generation",
    "sequence",
    "phase",
    "request_sheet",
    "request_segment",
    "permit_sequence",
    "permit_generation",
    "abort_sequence",
    "abort_generation",
    "complete_sequence",
    "complete_generation",
    "ack_sequence",
    "ack_generation",
    "fault",
    "gameplay_ready",
    "wait_count",
    "wait_limit",
)
OFF = {name: i * 4 for i, name in enumerate(FIELDS)}
STATE_SIZE = 0x50
MAGIC, VERSION = 0x52414243, 1
CODE_SIZE = 0x6000
FRAME = 0x400
DEP_CALL, CLEANUP_CALL = 0xE35CC, 0xE35D4
DEP_TARGET, CLEANUP_TARGET, SHEET_WAIT = 0xE2CC8, 0xE26D8, 0xE3978
READY_SITE, EXIT_SITE, EXIT_TARGET = 0x17500, 0x178D8, 0xC0CD0


def _u32(value):
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def initial_state(*, generation=1, wait_limit=600):
    if not _u32(generation) or not generation or not _u32(wait_limit):
        raise ValueError("nonzero uint32 generation and uint32 wait limit required")
    values = dict.fromkeys(FIELDS, 0)
    values.update(
        magic=MAGIC, version=VERSION, generation=generation, wait_limit=wait_limit
    )
    return struct.pack("<20I", *(values[n] for n in FIELDS), 0)


@dataclass(frozen=True)
class Config:
    g: int
    m: int
    code: int
    state: int

    def __post_init__(self):
        for address in (self.g, self.m, self.code, self.state):
            if (
                type(address) is not int
                or not 0x80000 <= address < 0x2000000
                or address % 16
            ):
                raise ValueError("physical EE addresses must be 16-byte aligned")
        spans = (
            (self.code, self.code + CODE_SIZE),
            (self.state, self.state + STATE_SIZE),
        )
        if (
            any(b > 0x2000000 for _, b in spans)
            or spans[0][0] < spans[1][1]
            and spans[1][0] < spans[0][1]
        ):
            raise ValueError("helper extent overflow or overlap")
        for address in guard_expectations(self):
            if address + 4 > 0x2000000 or any(
                a < address + 4 and address < b for a, b in spans
            ):
                raise ValueError("hook/guard overlaps helper or exceeds EE RAM")
        for address in (self.m + SHEET_WAIT, self.g + EXIT_TARGET):
            if address + 4 > 0x2000000 or any(a <= address < b for a, b in spans):
                raise ValueError("original function overlaps helper or exceeds EE RAM")


def _jal(address):
    return 0x0C000000 | (address >> 2)


def guard_expectations(c):
    """Exact code guards except loader-relocated data HI/LO immediates.

    The actual validated HI/LO words are copied, never reconstructed using g
    as a data base. The branch at READY_SITE+4 is explicitly relocated.
    """
    return {
        c.m + 0xE35BC: (0x0000302D, 0xFFFFFFFF),  # daddu a2, zero, zero
        c.m + DEP_CALL - 4: (0x8E440008, 0xFFFFFFFF),
        c.m + DEP_CALL: (_jal(c.m + DEP_TARGET), 0xFFFFFFFF),
        c.m + DEP_CALL + 4: (0x8E45000C, 0xFFFFFFFF),
        c.m + CLEANUP_CALL: (_jal(c.m + CLEANUP_TARGET), 0xFFFFFFFF),
        c.m + CLEANUP_CALL + 4: (0, 0xFFFFFFFF),
        c.g + READY_SITE - 8: (0x3C060000, 0xFFFF0000),
        c.g + READY_SITE - 4: (0, 0xFFFFFFFF),
        c.g + READY_SITE: (0x8CC20000, 0xFFFF0000),
        c.g + READY_SITE + 4: (0x10400019, 0xFFFFFFFF),
        c.g + READY_SITE + 8: (0x3C030000, 0xFFFF0000),
        c.g + EXIT_SITE: (_jal(c.g + EXIT_TARGET), 0xFFFFFFFF),
        c.g + EXIT_SITE + 4: (0, 0xFFFFFFFF),
    }


def validate_guards(c, words):
    for address, (expected, mask) in guard_expectations(c).items():
        value = words.get(address)
        if not _u32(value) or value & mask != expected:
            raise ValueError(f"unsupported NTSC-U instruction at {address:#x}")


def _load(reg, value):
    return [f"lui {reg}, 0x{value >> 16:x}", f"ori {reg}, {reg}, 0x{value & 65535:x}"]


def _save():
    # Save original SP before decrement, inside the frame about to be reserved.
    # AT is captured before scratch use; K0/K1 are volatile across interrupts.
    lines = ["sq $sp, -16($sp)", f"addiu $sp, $sp, -{FRAME}"]
    lines += [f"sq ${i}, {i * 16}($sp)" for i in range(1, 32) if i != 29]
    lines += [f"swc1 $f{i}, {0x200 + i * 4}($sp)" for i in range(32)]
    lines += [
        "pmfhi $at",
        "sq $at, 640($sp)",
        "pmflo $at",
        "sq $at, 656($sp)",
        "mfsa $at",
        "sw $at, 672($sp)",
        "cfc1 $at, $31",
        "sw $at, 676($sp)",
    ]
    return lines


def _restore():
    lines = [
        "lq $at, 640($sp)",
        "pmthi $at",
        "lq $at, 656($sp)",
        "pmtlo $at",
        "lw $at, 672($sp)",
        "mtsa $at",
        "lw $at, 676($sp)",
        "ctc1 $at, $31",
    ]
    lines += [f"lwc1 $f{i}, {0x200 + i * 4}($sp)" for i in range(32)]
    lines += [f"lq ${i}, {i * 16}($sp)" for i in range(1, 32) if i != 29]
    return lines + ["lq $sp, 1008($sp)"]


def render(c, words):
    validate_guards(c, words)
    out = [".set noreorder", ".set noat", '.section .text,"ax",@progbits', ".balign 16"]

    def emit(*lines):
        out.extend(lines)

    def branch(line):
        emit(line, "nop")

    def state():
        emit(*_load("$t0", c.state))

    def lw(reg, field):
        emit(f"lw {reg}, {OFF[field]}($t0)")

    def sw(reg, field):
        emit(f"sw {reg}, {OFF[field]}($t0)")

    def fault(label, flag, wait="blocked"):
        emit(label + ":")
        state()
        lw("$t1", "fault")
        emit(f"ori $t1, $t1, {int(flag)}")
        sw("$t1", "fault")
        branch("b " + wait)

    emit(".globl barrier_dependency", "barrier_dependency:", *_save())
    state()
    lw("$t1", "magic")
    emit(*_load("$t2", MAGIC))
    branch("bne $t1, $t2, bad_begin")
    lw("$t1", "version")
    emit("addiu $t2, $zero, 1")
    branch("bne $t1, $t2, bad_begin")
    lw("$t1", "generation")
    branch("beq $t1, $zero, bad_begin")
    lw("$t1", "phase")
    branch("bne $t1, $zero, nested")
    lw("$t1", "fault")
    branch("bne $t1, $zero, blocked")
    for complete, ack in (
        ("complete_sequence", "ack_sequence"),
        ("complete_generation", "ack_generation"),
    ):
        lw("$t1", complete)
        lw("$t2", ack)
        branch("bne $t1, $t2, unacknowledged")
    lw("$t1", "sequence")
    emit("addiu $t2, $zero, -1")
    branch("beq $t1, $t2, overflow")
    # Never consume a pre-authorized/stale command for a request not yet published.
    for field in (
        "permit_sequence",
        "permit_generation",
        "abort_sequence",
        "abort_generation",
    ):
        lw("$t2", field)
        branch("bne $t2, $zero, bad_begin")
    emit("addiu $t1, $t1, 1")
    sw("$t1", "sequence")
    emit("lw $t2, 64($sp)")  # low word of original a0
    sw("$t2", "request_sheet")
    emit("lw $t2, 80($sp)")  # low word of original a1
    sw("$t2", "request_segment")
    sw("$zero", "wait_count")
    sw("$zero", "gameplay_ready")
    lw("$t2", "sequence")
    emit("sw $t2, 680($sp)")
    lw("$t2", "generation")
    emit("sw $t2, 684($sp)")
    emit("sync", "addiu $t1, $zero, 1")
    sw("$t1", "phase")  # release-publication of request fields
    emit("sync", "watch:")
    state()
    lw("$t1", "fault")
    branch("bne $t1, $zero, sleep_wait")
    lw("$t1", "phase")
    emit("addiu $t2, $zero, 1")
    branch("bne $t1, $t2, bad_watch")
    # Snapshot epoch and sequence from entry publication; reject host mutation.
    lw("$t1", "sequence")
    emit("lw $t2, 680($sp)")
    # Frame-private identity was saved before WAIT publication.
    branch("bne $t1, $t2, bad_watch")
    lw("$t1", "generation")
    emit("lw $t2, 684($sp)")
    branch("bne $t1, $t2, bad_watch")
    for command, error in (("abort", "aborted"), ("permit", "permitted")):
        lw("$t1", command + "_sequence")
        lw("$t2", command + "_generation")
        emit("or $t3, $t1, $t2")
        branch(f"beq $t3, $zero, no_{command}")
        lw("$t3", "sequence")
        branch("bne $t1, $t3, unknown_permit")
        lw("$t3", "generation")
        branch("bne $t2, $t3, unknown_permit")
        branch("b " + error)
        emit("no_" + command + ":")
    lw("$t1", "wait_count")
    emit("addiu $t2, $zero, -1")
    branch("beq $t1, $t2, timed_out")
    emit("addiu $t1, $t1, 1")
    sw("$t1", "wait_count")
    lw("$t2", "wait_limit")
    branch("beq $t2, $zero, sleep_wait")
    emit("sltu $t3, $t1, $t2")
    branch("beq $t3, $zero, timed_out")
    emit("sleep_wait:")
    branch(f"jal 0x{c.m + SHEET_WAIT:x}")
    branch("b watch")
    emit("permitted:")
    # Retain accepted identity through cleanup; phase consumes the permit.
    emit("addiu $t1, $zero, 2", "sync")
    sw("$t1", "phase")
    emit("sync", *_restore())
    # Tail jump: original a0/a1/a2, SP and call-site RA are intact.
    branch(f"j 0x{c.m + DEP_TARGET:x}")
    fault("unknown_permit", Fault.UNKNOWN_PERMIT, "sleep_wait")
    fault("aborted", Fault.ABORT, "sleep_wait")
    fault("timed_out", Fault.TIMEOUT, "sleep_wait")
    fault("bad_watch", Fault.BAD_STATE, "sleep_wait")
    fault("nested", Fault.NESTED)
    fault("overflow", Fault.OVERFLOW)
    fault("unacknowledged", Fault.UNACKNOWLEDGED)
    fault("bad_begin", Fault.BAD_STATE)
    emit("blocked:")  # failed entry never returns or uses another request's permit
    branch(f"jal 0x{c.m + SHEET_WAIT:x}")
    branch("b blocked")
    emit(".globl barrier_cleanup", "barrier_cleanup:", *_save())
    state()
    lw("$t1", "phase")
    emit("addiu $t2, $zero, 2")
    branch("bne $t1, $t2, bad_cleanup")
    lw("$t1", "fault")
    branch("bne $t1, $zero, bad_cleanup")
    for current, accepted in (
        ("sequence", "permit_sequence"),
        ("generation", "permit_generation"),
    ):
        lw("$t1", current)
        lw("$t2", accepted)
        branch("bne $t1, $t2, bad_cleanup")
    # Restore original arguments, SP, FPU and GPRs, then interpose only RA.
    emit(*_restore())
    # Keep caller RA in the reserved frame; cleanup has no stack arguments.
    emit(f"addiu $sp, $sp, -{FRAME}")
    branch(f"jal 0x{c.m + CLEANUP_TARGET:x}")
    # Capture cleanup's actual result/clobbers before publishing completion.
    emit(*_save())
    state()
    lw("$t1", "sequence")
    sw("$t1", "complete_sequence")
    lw("$t1", "generation")
    sw("$t1", "complete_generation")
    sw("$zero", "permit_sequence")
    sw("$zero", "permit_generation")
    emit("sync")
    sw("$zero", "phase")
    emit("sync", *_restore(), "lq $ra, 496($sp)", "lq $sp, 1008($sp)")
    branch("jr $ra")
    fault("bad_cleanup", Fault.UNEXPECTED_CLEANUP)

    emit(".globl barrier_ready", "barrier_ready:", *_save())
    state()
    # This is a gameplay-loop observation, not authorization to spawn.
    emit("addiu $t1, $zero, 1")
    sw("$t1", "gameplay_ready")
    emit("sync", *_restore())
    emit(f".word 0x{words[c.g + READY_SITE]:08x}")
    branch("beq $v0, $zero, ready_taken")
    emit(f".word 0x{words[c.g + READY_SITE + 8]:08x}")
    branch(f"j 0x{c.g + READY_SITE + 12:x}")
    emit("ready_taken:", f".word 0x{words[c.g + READY_SITE + 8]:08x}")
    branch(f"j 0x{c.g + 0x1756C:x}")
    emit(".globl barrier_exit", "barrier_exit:", *_save())
    state()
    sw("$zero", "gameplay_ready")
    emit("sync", *_restore())
    branch(f"j 0x{c.g + EXIT_TARGET:x}")
    return "\n".join(out) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    """Assemble in temporary files and return an offline checked patch plan."""
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError(
                "explicit objcopy required when assembler lacks -as suffix"
            )
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-barriers-") as folder:
        source, output = Path(folder) / "barriers.s", Path(folder) / "barriers.o"
        source.write_text(assembly)
        subprocess.run(
            [
                str(assembler),
                "-EL",
                "-march=r5900",
                "-mabi=eabi",
                "-o",
                str(output),
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
                str(output),
            ],
            check=True,
            capture_output=True,
        )
        linked = link_object(
            output.read_bytes(),
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
        raise ValueError("barrier code exceeds reserved extent")
    patches = []
    for base, offset, name, call in (
        (c.m, DEP_CALL, "dependency", True),
        (c.m, CLEANUP_CALL, "cleanup", True),
        (c.g, READY_SITE, "ready", False),
        (c.g, EXIT_SITE, "exit", True),
    ):
        address, target = base + offset, linked.exports["barrier_" + name]
        if (address + 4) >> 28 != target >> 28:
            raise ValueError("hook outside J/JAL region")
        patches.append(
            WordPatch(
                address,
                words[address],
                (0x0C000000 if call else 0x08000000) | (target >> 2),
            )
        )
        if not call:
            patches.append(WordPatch(address + 4, words[address + 4], 0))
    return Build(assembly, linked, tuple(patches))


class Handshake:
    """Executable protocol model, not a live-memory transport.

    Host commands/ack/recovery require a coherent paused target in an actual
    integration. The model deliberately never dereferences request addresses.
    """

    def __init__(self, *, generation=1, wait_limit=600):
        self.values = dict(
            zip(
                FIELDS,
                struct.unpack(
                    "<20I", initial_state(generation=generation, wait_limit=wait_limit)
                )[:19],
            )
        )
        self.original_calls = self.cleanup_calls = 0
        self._identity = None

    def _fault(self, flag):
        self.values["fault"] |= int(flag)
        return False

    def begin(self, sheet, segment):
        v = self.values
        if not _u32(sheet) or not _u32(segment):
            raise ValueError("request fields must be uint32")
        if v["phase"] != Phase.IDLE:
            return self._fault(Fault.NESTED)
        if v["fault"]:
            return False
        if (v["complete_sequence"], v["complete_generation"]) != (
            v["ack_sequence"],
            v["ack_generation"],
        ):
            return self._fault(Fault.UNACKNOWLEDGED)
        if v["sequence"] == 0xFFFFFFFF:
            return self._fault(Fault.OVERFLOW)
        if (
            v["magic"] != MAGIC
            or v["version"] != VERSION
            or not v["generation"]
            or any(
                v[f]
                for f in (
                    "permit_sequence",
                    "permit_generation",
                    "abort_sequence",
                    "abort_generation",
                )
            )
        ):
            return self._fault(Fault.BAD_STATE)
        v.update(
            sequence=v["sequence"] + 1,
            request_sheet=sheet,
            request_segment=segment,
            wait_count=0,
            gameplay_ready=0,
            phase=Phase.WAIT,
        )
        self._identity = (v["generation"], v["sequence"])
        return True

    def command(self, sequence, generation, *, abort=False):
        if not _u32(sequence) or not _u32(generation):
            raise ValueError("command identity must be uint32")
        prefix = "abort" if abort else "permit"
        self.values[prefix + "_sequence"] = sequence
        self.values[prefix + "_generation"] = generation

    def tick(self):
        v = self.values
        if v["fault"] or v["phase"] == Phase.RELEASING:
            return False
        if (
            v["phase"] != Phase.WAIT
            or (v["generation"], v["sequence"]) != self._identity
        ):
            return self._fault(Fault.BAD_STATE)
        for prefix in ("abort", "permit"):
            identity = (v[prefix + "_generation"], v[prefix + "_sequence"])
            if identity != (0, 0):
                if identity != self._identity:
                    return self._fault(Fault.UNKNOWN_PERMIT)
                if prefix == "abort":
                    return self._fault(Fault.ABORT)
                v.update(phase=Phase.RELEASING)
                self.original_calls += 1
                return True
        if v["wait_count"] == 0xFFFFFFFF:
            return self._fault(Fault.TIMEOUT)
        v["wait_count"] += 1
        if v["wait_limit"] and v["wait_count"] >= v["wait_limit"]:
            return self._fault(Fault.TIMEOUT)
        return False

    def cleanup(self):
        v = self.values
        if (
            v["phase"] != Phase.RELEASING
            or v["fault"]
            or (v["sequence"], v["generation"])
            != (v["permit_sequence"], v["permit_generation"])
        ):
            return self._fault(Fault.UNEXPECTED_CLEANUP)
        self.cleanup_calls += 1
        v.update(
            complete_sequence=v["sequence"],
            complete_generation=v["generation"],
            permit_sequence=0,
            permit_generation=0,
            phase=Phase.IDLE,
        )
        return True

    def acknowledge(self, sequence, generation):
        v = self.values
        if (
            not _u32(sequence)
            or not _u32(generation)
            or v["phase"] != Phase.IDLE
            or v["fault"]
            or not sequence
            or (sequence, generation)
            != (v["complete_sequence"], v["complete_generation"])
        ):
            raise ValueError("acknowledgement must match the completed request")
        v.update(ack_sequence=sequence, ack_generation=generation)

    def recover_wait(self, sequence, generation):
        """Explicit paused-host recovery after independently revalidating drain.

        This only clears recoverable WAIT faults; it does not grant a permit.
        Entry/nesting/overflow faults require restoring a known-safe epoch.
        """
        v = self.values
        fatal = (
            Fault.NESTED
            | Fault.OVERFLOW
            | Fault.UNACKNOWLEDGED
            | Fault.BAD_STATE
            | Fault.UNEXPECTED_CLEANUP
        )
        if (
            not _u32(sequence)
            or not _u32(generation)
            or v["phase"] != Phase.WAIT
            or (generation, sequence) != self._identity
            or v["fault"] & fatal
        ):
            raise ValueError("not a recoverable pending request")
        v.update(
            fault=0,
            permit_sequence=0,
            permit_generation=0,
            abort_sequence=0,
            abort_generation=0,
            wait_count=0,
        )
