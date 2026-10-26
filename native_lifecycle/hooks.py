"""Offline, project-authored EE lifecycle call wrappers (NTSC-U only).

No installation or target I/O occurs here. G/K are loaded listing origins
(actual .text minus 0x38 for this revision). The caller
must reserve code/context and attest trusted_code ranges; bounds are not proof
of ownership. Externals are fixed at link time, never read from host commands.
canonical_group is the *address* gcGlobalVar+0x2b0, not its first word.

Both call sites have register-only EE EABI arguments (a0-a3, t0-t3). Original
callees see these unchanged after the original delay slot, with a private,
16-byte-aligned stack and normal call RA. Callbacks/get_first must obey EE EABI,
return without yielding/reentry, and not touch FPACC or VU state. Their GP needs
must be handled by their bound entry thunks. Integer glue does no FPACC/VU
arithmetic; these unobservable states cannot be saved by this wrapper. FPRs,
FCSR, full 128-bit GPRs/HI/LO and SA are restored from the actual chained call,
except SP/RA, which return to the outer caller as required by the ABI.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

ADMISSION_CALL = 0x1B324
FREE_CALL = 0x1975C
CODE_SIZE = 0x2000
FRAME = 0x400
GPRS = 0x80
FPRS = 0x280
HI, LO, SA, FCSR = 0x300, 0x310, 0x320, 0x324
OUTER_RA, ACTOR, GROUP, OUTER_SP = 0x330, 0x350, 0x360, 0x3F0


def _address(value, alignment=4):
    return type(value) is int and 0x80000 <= value < 0x2000000 and not value % alignment


def _jal(address):
    return 0x0C000000 | (address >> 2)


@dataclass(frozen=True)
class Config:
    g: int
    k: int
    code: int
    context: int
    context_size: int
    original_group_add: int
    previous_free_target: int
    expected_group_call: int
    expected_free_call: int
    canonical_group: int
    get_first: int
    canonical_admitted: int
    allocation_freed: int
    # Explicitly attested project-owned executable ranges: (base, byte size).
    trusted_code: tuple[tuple[int, int], ...]

    def __post_init__(self):
        for value in (self.g, self.k, self.code, self.context):
            if not _address(value, 16):
                raise ValueError(
                    "module/code/context bases must be aligned physical EE addresses"
                )
        for value in (
            self.original_group_add,
            self.previous_free_target,
            self.canonical_group,
            self.get_first,
            self.canonical_admitted,
            self.allocation_freed,
        ):
            if not _address(value):
                raise ValueError("invalid external physical EE address")
        if type(self.context_size) is not int or self.context_size <= 0:
            raise ValueError("owned context extent required")
        spans = [(self.code, CODE_SIZE), (self.context, self.context_size)]
        for base, size in self.trusted_code:
            if not _address(base, 16) or type(size) is not int or size <= 0:
                raise ValueError("invalid trusted code extent")
            spans.append((base, size))
        for i, (base, size) in enumerate(spans):
            if base + size > 0x2000000:
                raise ValueError("owned extent exceeds EE RAM")
            if any(base < b + n and b < base + size for b, n in spans[:i]):
                raise ValueError("owned extents overlap")

        def trusted(address):
            return any(
                b <= address and address + 4 <= b + n for b, n in self.trusted_code
            )

        if not all(
            trusted(a) for a in (self.canonical_admitted, self.allocation_freed)
        ):
            raise ValueError("callbacks must be bound to trusted owned code")
        if self.previous_free_target != self.k + 0x39C8 and not trusted(
            self.previous_free_target
        ):
            raise ValueError("non-stock previous free must be trusted owned code")
        for word, target in (
            (self.expected_group_call, self.original_group_add),
            (self.expected_free_call, self.previous_free_target),
        ):
            if type(word) is not int or word != _jal(target):
                raise ValueError("expected actual JAL must match chained target")
        for address in guard_expectations(self):
            if not _address(address) or any(b <= address < b + n for b, n in spans):
                raise ValueError("guard exceeds RAM or overlaps owned memory")
        for address in (self.original_group_add, self.get_first, self.canonical_group):
            if any(b <= address < b + n for b, n in spans):
                raise ValueError("stock binding overlaps owned memory")


def guard_expectations(c):
    """Exact call/delay and loadObj actor/group setup; no relaxed masks."""
    return {
        c.g + 0x1B30C: 0x86250008,  # lh a1,8(s1)
        c.g + 0x1B310: 0x26020024,  # addiu v0,s0,0x24
        c.g + 0x1B314: 0x0240202D,  # daddu a0,s2,zero
        c.g + 0x1B318: 0x0000302D,
        c.g + 0x1B31C: 0x00052880,
        c.g + 0x1B320: 0x0000382D,
        c.g + ADMISSION_CALL: c.expected_group_call,
        c.g + ADMISSION_CALL + 4: 0x00A22821,
        c.g + ADMISSION_CALL + 8: 0x10000107,
        c.g + ADMISSION_CALL + 12: 0,
        c.k + FREE_CALL - 4: 0x8E240000,
        c.k + FREE_CALL: c.expected_free_call,
        c.k + FREE_CALL + 4: 0x0200882D,
    }


def validate_guards(c, words):
    for address, expected in guard_expectations(c).items():
        if type(words.get(address)) is not int or words[address] != expected:
            raise ValueError(f"unsupported lifecycle instruction at {address:#x}")


def _load(reg, symbol):
    return [f"lui {reg}, %hi({symbol})", f"addiu {reg}, {reg}, %lo({symbol})"]


def _capture():
    # Save AT before using it as scratch. Interrupts may destroy K0/K1.
    lines = [f"sq ${i}, {GPRS + i * 16}($sp)" for i in range(1, 32) if i != 29]
    lines += [f"swc1 $f{i}, {FPRS + i * 4}($sp)" for i in range(32)]
    lines += [
        "pmfhi $at",
        f"sq $at, {HI}($sp)",
        "pmflo $at",
        f"sq $at, {LO}($sp)",
        "mfsa $at",
        f"sw $at, {SA}($sp)",
        "cfc1 $at, $31",
        f"sw $at, {FCSR}($sp)",
    ]
    return lines


def _restore():
    lines = [
        f"lq $at, {HI}($sp)",
        "pmthi $at",
        f"lq $at, {LO}($sp)",
        "pmtlo $at",
        f"lw $at, {SA}($sp)",
        "mtsa $at",
        f"lw $at, {FCSR}($sp)",
        "ctc1 $at, $31",
    ]
    lines += [f"lwc1 $f{i}, {FPRS + i * 4}($sp)" for i in range(32)]
    lines += [f"lq ${i}, {GPRS + i * 16}($sp)" for i in range(1, 31) if i != 29]
    return lines + [
        f"lq $ra, {OUTER_RA}($sp)",
        f"lq $sp, {OUTER_SP}($sp)",
        "jr $ra",
        "nop",
    ]


def render(c, words):
    validate_guards(c, words)
    lines = [
        ".set noreorder",
        ".set noat",
        '.section .text,"ax",@progbits',
        ".balign 16",
    ]
    for name, target in (
        ("canonical_admission", "original_group_add"),
        ("final_free", "previous_free_target"),
    ):
        lines += [
            f".globl hook_{name}",
            f"hook_{name}:",
            "sq $sp, -16($sp)",
            f"addiu $sp, $sp, -{FRAME}",
            f"sq $ra, {OUTER_RA}($sp)",
            f"sq $a0, {ACTOR}($sp)",
            f"sq $a1, {GROUP}($sp)",
            f"jal {target}",
            "nop",
        ]
        lines += _capture()
        if name == "canonical_admission":
            lines += [
                "beq $v0, $zero, admission_done",
                "nop",
                f"lw $t0, {ACTOR}($sp)",
                "beq $t0, $zero, admission_done",
                "nop",
                f"lw $a0, {GROUP}($sp)",
            ]
            lines += _load("$t0", "canonical_group")
            lines += [
                "bne $a0, $t0, admission_done",
                "nop",
                "jal get_first",
                "nop",
                f"lw $t0, {ACTOR}($sp)",
                "bne $v0, $t0, admission_done",
                "nop",
            ]
            lines += _load("$a0", "callback_context")
            lines += [
                f"lw $a1, {ACTOR}($sp)",
                "jal canonical_admitted",
                "nop",
                "admission_done:",
            ]
        else:
            lines += _load("$a0", "callback_context")
            lines += [f"lw $a1, {ACTOR}($sp)", "jal allocation_freed", "nop"]
        lines += _restore()
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    """Optional PS2DEV assembly/link; return payload and unapplied WordPatch plan."""
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler name")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-lifecycle-") as folder:
        source, output = Path(folder) / "hooks.s", Path(folder) / "hooks.o"
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
        externals = {
            name: getattr(c, name)
            for name in (
                "original_group_add",
                "previous_free_target",
                "canonical_group",
                "get_first",
                "canonical_admitted",
                "allocation_freed",
            )
        }
        externals["callback_context"] = c.context
        linked = link_object(
            output.read_bytes(),
            {
                ".text": c.code,
                ".data": c.code + CODE_SIZE - 32,
                ".bss": c.code + CODE_SIZE - 16,
            },
            externals,
        )
    if any(
        p.address < c.code or p.address + len(p.data) > c.code + CODE_SIZE
        for p in linked.payloads
    ):
        raise ValueError("wrapper exceeds owned code extent")
    patches = tuple(
        WordPatch(address, words[address], _jal(linked.exports[name]))
        for address, name in (
            (c.g + ADMISSION_CALL, "hook_canonical_admission"),
            (c.k + FREE_CALL, "hook_final_free"),
        )
    )
    return Build(assembly, linked, patches)
