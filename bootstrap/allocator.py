"""Offline one-shot allocation at the stock main-loop USB call.

All module addresses are loaded .text bases. No transport or installer is
provided. Relocated cave bytes are caller-supplied provenance, not discovered
by treating whatever happens to be in RAM as original code.
"""

import hashlib
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch
from runtime.xff import parse

RAM_SIZE = 0x2000000
CAVE_OFFSET, CAVE_SIZE = 0x4A40, 0x3D4
CALL_OFFSET, USB_OFFSET, ALLOC_OFFSET = 0xC640, 0xD05B8, 0x3758
FRAME_SIZE = 0x300
STATE_SIZE = 16
GAMECORE_SHA256 = "fba772ac8c793281af15be204243098b999e91b229ad3074a39a9773a56676f9"


def _region(address, size, alignment=4):
    if (
        type(address) is not int
        or type(size) is not int
        or size <= 0
        or address < 0x80000
        or address % alignment
        or address + size > RAM_SIZE
    ):
        raise ValueError("invalid physical EE RAM extent")


def _jal(address):
    _region(address, 4)
    return 0x0C000000 | (address >> 2)


@dataclass(frozen=True)
class AllocationSpec:
    g: int
    k: int
    m: int
    cave: int
    original_cave: bytes
    root_heap: int
    requested_size: int
    allocator: int
    allocator_gp: int
    # Explicit evidence references, not Boolean defaults that imply safety.
    unused_attestation: str
    quiescence_attestation: str
    provenance_attestation: str
    stack_attestation: str
    alignment: int = 16

    def __post_init__(self):
        for base in (self.g, self.k, self.m):
            _region(base, 4)
        _region(self.cave, CAVE_SIZE)
        if self.cave != self.g + CAVE_OFFSET:
            raise ValueError(
                "only the complete original DebugSnapShot extent is supported"
            )
        if (
            not isinstance(self.original_cave, bytes)
            or len(self.original_cave) != CAVE_SIZE
        ):
            raise ValueError("require all original relocated DebugSnapShot bytes")
        if self.allocator != self.k + ALLOC_OFFSET:
            raise ValueError("allocator must be original iosMallocAlignNoCheck")
        for address in (self.root_heap, self.allocator, self.allocator_gp):
            _region(address, 4)
        if (
            type(self.requested_size) is not int
            or not 0x10000 <= self.requested_size <= 0x200000
        ):
            raise ValueError("allocation size must be 64 KiB through 2 MiB")
        if self.alignment != 16:
            raise ValueError(
                "only the qualified 16-byte allocation alignment is supported"
            )
        for evidence in (
            self.unused_attestation,
            self.quiescence_attestation,
            self.provenance_attestation,
            self.stack_attestation,
        ):
            if not isinstance(evidence, str) or not evidence.strip():
                raise ValueError(
                    "explicit unused/provenance/quiescence/stack attestations required"
                )
        for address, size in (
            (self.g + CALL_OFFSET, 8),
            (self.m + USB_OFFSET, 8),
            (self.allocator, 16),
            (self.root_heap, 4),
            (self.allocator_gp, 4),
        ):
            _region(address, size)
            if address < self.cave + CAVE_SIZE and self.cave < address + size:
                raise ValueError("bootstrap cave overlaps a dependency")

    @property
    def state(self):
        return (self.cave + CAVE_SIZE - STATE_SIZE) & ~15


@dataclass(frozen=True)
class AllocationPlan:
    source: str
    object_bytes: bytes
    code: bytes
    code_address: int
    state_address: int
    state_bytes: bytes
    patches: tuple[WordPatch, ...]
    guards: tuple[tuple[int, bytes], ...]
    original_cave: bytes
    # Recovery data is NOT a receipt: actual writes need runtime receipts.
    restore_call: WordPatch


def validate_original(spec: AllocationSpec, original_gamecore: bytes):
    """Bind the proposed cave to the known original named function.

    Relocation operands are deliberately NOT authenticated by opcode matching.
    The caller must independently certify original_cave's relocated operands
    in provenance_attestation. This routine checks the original source hash,
    exact symbol extent and every non-relocated instruction bit.
    """
    if hashlib.sha256(original_gamecore).hexdigest() != GAMECORE_SHA256:
        raise ValueError("wrong original GAMECORE fingerprint")
    module = parse(original_gamecore)
    text_id = module.index_of(".text")
    symbols = [
        module.symbol(i)
        for i in range(module.num_symbols)
        if module.symbol_name(i) == "DebugSnapShot"
    ]
    if (
        len(symbols) != 1
        or symbols[0][1:3] != (CAVE_OFFSET, CAVE_SIZE)
        or symbols[0][5] != text_id
    ):
        raise ValueError("unverified DebugSnapShot symbol extent")
    original = module.sections[text_id].data[CAVE_OFFSET : CAVE_OFFSET + CAVE_SIZE]
    masks = {}
    for table in module.reltables:
        if table.target != text_id:
            continue
        for offset, info, _, _ in table.entries:
            if CAVE_OFFSET <= offset < CAVE_OFFSET + CAVE_SIZE:
                kind = info & 255
                if kind not in (4, 5, 6):
                    raise ValueError("unsupported cave relocation")
                masks[offset - CAVE_OFFSET] = 0xFC000000 if kind == 4 else 0xFFFF0000
    for offset in range(0, CAVE_SIZE, 4):
        mask = masks.get(offset, 0xFFFFFFFF)
        before = int.from_bytes(original[offset : offset + 4], "little")
        supplied = int.from_bytes(spec.original_cave[offset : offset + 4], "little")
        if before & mask != supplied & mask:
            raise ValueError(f"non-original cave instruction at {offset:#x}")


def guard_expectations(spec: AllocationSpec):
    """Exact observed bytes, including the whole caller-certified cave."""
    words = {
        spec.g + CALL_OFFSET: _jal(spec.m + USB_OFFSET),
        spec.g + CALL_OFFSET + 4: 0,
        spec.m + USB_OFFSET: 0x27BDFFF0,
        spec.m + USB_OFFSET + 4: 0xFFB00000,
        spec.allocator: 0x27BDFFD0,
        spec.allocator + 4: 0xFFB00000,
        spec.allocator + 12: 0xFFB10008,
    }
    return (
        (spec.cave, spec.original_cave),
        *(
            (address, word.to_bytes(4, "little"))
            for address, word in sorted(words.items())
        ),
    )


def render(spec: AllocationSpec):
    """Authored R5900 assembly. State words: status, base, raw result, error.

    status 0 -> 1 -> 2/3, errors 1=null, 2=invalid range/alignment/overlap.
    State 1 is sticky if the native call never returns. No automatic retry.
    """
    lines = [
        ".set noreorder",
        ".set noat",
        ".text",
        ".globl bootstrap_alloc",
        "bootstrap_alloc:",
        f"sq $sp, {64 + 28 * 16 - FRAME_SIZE}($sp)",
        f"addiu $sp, $sp, -{FRAME_SIZE}",
    ]
    # Preserve even caller-saved registers: USB must see the untouched input.
    for register in range(1, 32):
        if register != 29:
            lines.append(f"sq ${register}, {64 + (register - 1) * 16}($sp)")
    for register in range(32):
        lines.append(f"swc1 $f{register}, {560 + register * 4}($sp)")
    lines += [
        "pmfhi $t0",
        "sq $t0, 688($sp)",
        "pmflo $t0",
        "sq $t0, 704($sp)",
        "mfsa $t0",
        "sw $t0, 720($sp)",
        "cfc1 $t0, $31",
        "sw $t0, 724($sp)",
    ]

    def load(reg, value):
        return [f"lui {reg}, {value >> 16}", f"ori {reg}, {reg}, {value & 65535}"]

    lines += load("$s0", spec.state)
    lines += [
        "lw $t0, 0($s0)",
        "bne $t0, $zero, restore",
        "nop",
        "addiu $t0, $zero, 1",
        "sw $t0, 0($s0)",
        "sync",
    ]
    lines += load("$a0", spec.root_heap) + load("$a1", spec.requested_size)
    lines += load("$gp", spec.allocator_gp)
    lines += [
        "addiu $a2, $zero, 16",
        "jal original_allocator",
        "nop",
        "sw $v0, 8($s0)",
        "beq $v0, $zero, null_result",
        "nop",
        "andi $t0, $v0, 15",
        "bne $t0, $zero, invalid_result",
        "nop",
    ]
    lines += load("$t1", 0x80000)
    lines += ["sltu $t0, $v0, $t1", "bne $t0, $zero, invalid_result", "nop"]
    lines += load("$t1", RAM_SIZE - spec.requested_size)
    lines += ["sltu $t0, $t1, $v0", "bne $t0, $zero, invalid_result", "nop"]
    # A malformed native return must not certify its own bootstrap as allocated.
    lines += load("$t1", spec.requested_size)
    lines += ["addu $t2, $v0, $t1"] + load("$t1", spec.cave)
    lines += ["sltu $t0, $t1, $t2", "beq $t0, $zero, valid_result", "nop"]
    lines += load("$t1", spec.cave + CAVE_SIZE)
    lines += [
        "sltu $t0, $v0, $t1",
        "bne $t0, $zero, invalid_result",
        "nop",
        "valid_result:",
        "sw $v0, 4($s0)",
        "sync",
        "addiu $t0, $zero, 2",
        "sw $t0, 0($s0)",
        "b restore",
        "nop",
        "null_result:",
        "addiu $t0, $zero, 1",
        "b failed",
        "nop",
        "invalid_result:",
        "addiu $t0, $zero, 2",
        "failed:",
        "sw $t0, 12($s0)",
        "sync",
        "addiu $t0, $zero, 3",
        "sw $t0, 0($s0)",
        "restore:",
        "lq $t0, 688($sp)",
        "pmthi $t0",
        "lq $t0, 704($sp)",
        "pmtlo $t0",
        "lw $t0, 720($sp)",
        "mtsa $t0",
        "lw $t0, 724($sp)",
        "ctc1 $t0, $31",
    ]
    for register in range(32):
        lines.append(f"lwc1 $f{register}, {560 + register * 4}($sp)")
    for register in range(1, 32):
        if register != 29:
            lines.append(f"lq ${register}, {64 + (register - 1) * 16}($sp)")
    lines += [f"lq $sp, {64 + 28 * 16}($sp)", "j original_usb", "nop"]
    return "\n".join(lines) + "\n"


def build(
    spec: AllocationSpec,
    original_gamecore: bytes,
    read: Callable[[int, int], bytes],
    *,
    assembler: str | Path,
    objcopy: str | Path | None = None,
):
    """Verify supplied observations and return an unapplied, immutable plan.

    The read callback must be a stable offline snapshot (not a live writer).
    Temporary assembler files are local build products only.
    """
    validate_original(spec, original_gamecore)
    guards = guard_expectations(spec)
    for address, expected in guards:
        if read(address, len(expected)) != expected:
            raise ValueError(f"original guard mismatch at {address:#x}")
    source = render(spec)
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler name")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="sotc-bootstrap-") as directory:
        root = Path(directory)
        (root / "allocator.s").write_text(source)
        subprocess.run(
            [
                str(assembler),
                "-EL",
                "-march=r5900",
                "-mabi=eabi",
                "-o",
                str(root / "allocator.o"),
                str(root / "allocator.s"),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(objcopy),
                "--remove-section=.MIPS.abiflags",
                "--remove-section=.reginfo",
                str(root / "allocator.o"),
            ],
            check=True,
            capture_output=True,
        )
        obj = (root / "allocator.o").read_bytes()
    linked = link_object(
        obj,
        {".text": spec.cave, ".data": spec.cave, ".bss": spec.cave},
        externals={
            "original_allocator": spec.allocator,
            "original_usb": spec.m + USB_OFFSET,
        },
    )
    text = next(payload for payload in linked.payloads if payload.section == ".text")
    if spec.cave + len(text.data) > spec.state:
        raise ValueError("allocator code overlaps result state")
    patch = WordPatch(spec.g + CALL_OFFSET, _jal(spec.m + USB_OFFSET), _jal(spec.cave))
    return AllocationPlan(
        source,
        obj,
        text.data,
        spec.cave,
        spec.state,
        bytes(STATE_SIZE),
        (patch,),
        guards,
        spec.original_cave,
        WordPatch(patch.address, patch.replacement, patch.expected),
    )
