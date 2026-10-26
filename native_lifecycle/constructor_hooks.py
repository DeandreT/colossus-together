"""Offline NTSC-U constructor-entry wrappers, chained after existing telemetry.

The caller must hash-whitelist the exact previous hook implementations (including
their trampolines) before attesting ``trusted_code``. Address bounds and the J/nop
guards alone do NOT establish that code's identity. Never infer a chain target
from unknown live instructions. No target I/O or installation is performed here.

Only 128 bytes are held across the original constructor; the full state frame is
allocated after it returns. Even this extra stack use requires external live P1
stack qualification. The observer must return synchronously without reentry,
handle its own GP, and must not modify FPACC or VU state. Like the lifecycle
wrappers, all observable post-call integer/FPU state is preserved except that
SP/RA are restored to the original caller. All eight EE EABI argument registers
reach the previous constructor unchanged.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

from .hooks import (
    CODE_SIZE,
    FRAME,
    GPRS,
    OUTER_RA,
    OUTER_SP,
    _address,
    _capture,
    _load,
    _restore,
)

CHARACTER, ALIAS = 0, 1
CHAR_ENTRY, ALIAS_ENTRY = 0x832D8, 0x82FA0
PRE_FRAME = 128
PRE_RA, DEFINITION, PARAMETERS, PRE_SP = 64, 80, 96, 112
FAMILY = 0x370


def _j(address):
    return 0x08000000 | (address >> 2)


@dataclass(frozen=True)
class Config:
    m: int
    code: int
    context: int
    context_size: int
    previous_char_entry: int
    previous_alias_entry: int
    expected_char_entry: tuple[int, int]
    expected_alias_entry: tuple[int, int]
    observe: int
    trusted_code: tuple[tuple[int, int], ...]

    def __post_init__(self):
        if not all(_address(a, 16) for a in (self.m, self.code, self.context)):
            raise ValueError("module/code/context bases must be aligned EE addresses")
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
        for target in (
            self.previous_char_entry,
            self.previous_alias_entry,
            self.observe,
        ):
            if not _address(target) or not any(
                b <= target and target + 4 <= b + n for b, n in self.trusted_code
            ):
                raise ValueError("previous entries and observer must be trusted code")
            if (self.code + 4) >> 28 != target >> 28:
                raise ValueError("call target outside JAL segment")
        for offset, expected, target in (
            (CHAR_ENTRY, self.expected_char_entry, self.previous_char_entry),
            (ALIAS_ENTRY, self.expected_alias_entry, self.previous_alias_entry),
        ):
            if (
                not isinstance(expected, tuple)
                or len(expected) != 2
                or any(type(w) is not int for w in expected)
                or expected != (_j(target), 0)
            ):
                raise ValueError("expected entry must be exact trusted previous J/nop")
            if (self.m + offset + 4) >> 28 != self.code >> 28:
                raise ValueError("replacement outside J segment")
            if any(
                b < self.m + offset + 0x28 and self.m + offset < b + n for b, n in spans
            ):
                raise ValueError("constructor prologue overlaps owned memory")
        for address in guard_expectations(self):
            if not _address(address) or any(
                b < address + 4 and address < b + n for b, n in spans
            ):
                raise ValueError("guard exceeds RAM or overlaps owned memory")


def guard_expectations(c):
    """Exact current entries and remaining stock prologue words, never masks."""
    return {
        c.m + CHAR_ENTRY: c.expected_char_entry[0],
        c.m + CHAR_ENTRY + 4: c.expected_char_entry[1],
        c.m + CHAR_ENTRY + 0x14: 0xFFB002C0,
        c.m + CHAR_ENTRY + 0x18: 0xFFB402E0,
        c.m + CHAR_ENTRY + 0x24: 0x00C0802D,
        c.m + ALIAS_ENTRY: c.expected_alias_entry[0],
        c.m + ALIAS_ENTRY + 4: c.expected_alias_entry[1],
        c.m + ALIAS_ENTRY + 8: 0xFFB00120,
        c.m + ALIAS_ENTRY + 12: 0x00A0802D,
    }


def validate_guards(c, words):
    for address, expected in guard_expectations(c).items():
        if type(words.get(address)) is not int or words[address] != expected:
            raise ValueError(f"unsupported constructor instruction at {address:#x}")


def render(c, words):
    validate_guards(c, words)
    lines = [".set noreorder", ".set noat", '.section .text,"ax",@progbits']
    for name, target, family in (
        ("character", "previous_char_entry", CHARACTER),
        ("alias", "previous_alias_entry", ALIAS),
    ):
        lines += [
            ".balign 16",
            f".globl hook_{name}",
            f"hook_{name}:",
            "sq $sp, -16($sp)",
            f"addiu $sp, $sp, -{PRE_FRAME}",
            f"sq $ra, {PRE_RA}($sp)",
            f"sq $a1, {DEFINITION}($sp)",
            f"sq $a2, {PARAMETERS}($sp)",
            f"jal {target}",
            "nop",
            f"addiu $sp, $sp, -{FRAME}",
        ]
        lines += _capture()
        # AT's full post-call value was captured before using it as scratch.
        lines += [
            f"lq $at, {FRAME + PRE_RA}($sp)",
            f"sq $at, {OUTER_RA}($sp)",
            f"lq $at, {FRAME + PRE_SP}($sp)",
            f"sq $at, {OUTER_SP}($sp)",
            "beq $v0, $zero, done_" + name,
            "nop",
            f"addiu $a3, $zero, {family}",
            f"sw $a3, {FAMILY}($sp)",
        ]
        lines += _load("$a0", "callback_context")
        lines += [
            f"lq $a1, {GPRS + 2 * 16}($sp)",
            f"lw $a2, {FRAME + DEFINITION}($sp)",
            f"lw $a3, {FAMILY}($sp)",
            "jal observe",
            "nop",
            f"done_{name}:",
        ]
        lines += _restore()
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    """Assemble/link an offline payload and unapplied fixed J/nop entry plan.

    Nop words are guards only: emitting no-op WordPatches would be rejected by
    the shared patch transaction API. No bytes beyond each 8-byte entry change.
    """
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler name")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-constructors-") as folder:
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
        linked = link_object(
            output.read_bytes(),
            {
                ".text": c.code,
                ".data": c.code + CODE_SIZE - 32,
                ".bss": c.code + CODE_SIZE - 16,
            },
            {
                "previous_char_entry": c.previous_char_entry,
                "previous_alias_entry": c.previous_alias_entry,
                "observe": c.observe,
                "callback_context": c.context,
            },
        )
    if any(
        p.address < c.code or p.address + len(p.data) > c.code + CODE_SIZE
        for p in linked.payloads
    ):
        raise ValueError("wrapper exceeds owned code extent")
    patches = []
    for offset, name in ((CHAR_ENTRY, "character"), (ALIAS_ENTRY, "alias")):
        address, target = c.m + offset, linked.exports["hook_" + name]
        if (address + 4) >> 28 != target >> 28:
            raise ValueError("replacement outside J segment")
        patches.append(WordPatch(address, words[address], _j(target)))
    return Build(assembly, linked, tuple(patches))
