"""Offline NTSC-U Game Over Retry policy seam; never installs or runs a patch.

Only G+0x552b0 is replaced. Its original NOP delay remains in place; scrRun is
called once with unchanged register arguments on a 96-byte coroutine-resident
frame. Policy runs only after that call RETURNS (not while it is suspended),
after the native menu update/draw. A separate post-call frame preserves full
128-bit GPR/HI/LO, SA, FPR and FCSR state; outer SP/RA are restored on return.
No FPACC/VU state is touched by glue; both callbacks must also leave it alone.

The caller verifies the loaded revision, resolved scrRun and D_0017ABB8 address,
reserves code/context, and supplies trusted synchronous, non-reentrant callbacks
with their own GP handling and normal stack discipline. should_retry(context)
must be read-only: true ONLY for enabled co-op, the current unconsumed death
epoch, QUIESCENT fully retired P2, no held resources/owned references, and a ready
main Game Over menu. The wrapper does not guess UI strings or readiness offsets.
retry_selected(context) consumes that epoch once, after the state 0 -> 1 store.
These are provider obligations, not safety established by address validation.

Native state 1 performs Retry's fade/wait, result 0, ScrSpriteParamEnd completion,
and st_gameflow's checkpoint reload. Neither completion pointers nor gameflow
results are forced here. A second state check after should_retry protects Quit
even from a misbehaving callback. Only this one engine-owned outcome word may
be changed; there is no global scrRun hook, restart call, key injection or BSS.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

from .hooks import FRAME as POST_FRAME
from .hooks import OUTER_RA, OUTER_SP, _address, _capture, _jal, _load, _restore

CALL_OFFSET = 0x552B0
CODE_SIZE = 0x400
PRE_FRAME, PRE_SP, PRE_RA = 96, 64, 80


@dataclass(frozen=True)
class Config:
    g: int
    original_scr_run: int
    expected_call: int
    state: int
    code: int
    context: int
    context_size: int
    should_retry: int
    retry_selected: int
    trusted_code: tuple[tuple[int, int], ...]

    @property
    def call_site(self):
        return self.g + CALL_OFFSET

    def __post_init__(self):
        for address in (self.g, self.code, self.context):
            if not _address(address, 16):
                raise ValueError(
                    "module/code/context must be aligned physical EE addresses"
                )
        for address in (
            self.original_scr_run,
            self.state,
            self.should_retry,
            self.retry_selected,
        ):
            if not _address(address):
                raise ValueError("invalid external physical EE address")
        if type(self.expected_call) is not int or self.expected_call != _jal(
            self.original_scr_run
        ):
            raise ValueError("expected JAL must match resolved original scrRun")
        if type(self.context_size) is not int or self.context_size <= 0:
            raise ValueError("owned context extent required")
        spans = [
            (self.code, CODE_SIZE),
            (self.context, self.context_size),
            (self.state, 4),
        ]
        for base, size in self.trusted_code:
            if not _address(base) or type(size) is not int or size <= 0 or size % 4:
                raise ValueError("invalid trusted code extent")
            spans.append((base, size))
        for i, (base, size) in enumerate(spans):
            if base + size > 0x2000000:
                raise ValueError("extent exceeds physical EE RAM")
            if any(base < b + n and b < base + size for b, n in spans[:i]):
                raise ValueError("code/context/state/trusted extents overlap")
        for target in (self.original_scr_run, self.should_retry, self.retry_selected):
            if not any(
                b <= target and target + 4 <= b + n for b, n in self.trusted_code
            ):
                raise ValueError("callee must be in attested trusted code")
            if self.g + 0x54E68 <= target < self.g + 0x55390:
                raise ValueError("callee overlaps Game Over routine")
        if self.should_retry == self.retry_selected or self.original_scr_run in (
            self.should_retry,
            self.retry_selected,
        ):
            raise ValueError("original and policy callbacks must be distinct")
        for address in guard_expectations(self):
            if not _address(address) or any(b <= address < b + n for b, n in spans[:3]):
                raise ValueError("guard exceeds RAM or overlaps owned memory/state")
        for base, size in spans[:3]:
            if base < self.g + 0x55390 and self.g + 0x54E68 < base + size:
                raise ValueError("owned memory/state overlaps Game Over routine")


def guard_expectations(c):
    """Resolved state references plus exact native update/draw/yield loop words."""
    lo = c.state & 0xFFFF
    return {
        c.g + 0x55000: 0x3C130000 | ((c.state + 0x8000) >> 16),  # lui s3,state
        c.g + 0x550D0: 0xAE600000 | lo,  # sw zero,state(s3): initialized once
        c.g + 0x550D4: 0x8E630000 | lo,  # lw v1,state(s3)
        c.g + 0x550D8: 0x2C620009,  # sltiu v0,v1,9: native state dispatch
        c.g + 0x55284: 0x0220282D,  # daddu a1,s1,zero
        c.g + 0x5528C: 0x8EC30028,  # update method
        c.g + 0x55294: 0x0240202D,
        c.g + 0x55298: 0x0000302D,
        c.g + 0x5529C: 0x0060F809,  # jalr v1
        c.g + 0x552A0: 0x0000382D,
        c.g + 0x552A4: 0x8EC2002C,  # draw method
        c.g + 0x552A8: 0x0040F809,
        c.g + 0x552AC: 0x0240202D,
        c.call_site: c.expected_call,
        c.call_site + 4: 0,  # retain this exact original delay
        c.g + 0x552B8: 0x16A0FF87,  # bnez s5,550d8
        c.g + 0x552BC: 0x8E630000 | lo,  # state reloaded in branch delay
    }


def validate_guards(c, words):
    for address, expected in guard_expectations(c).items():
        if type(words.get(address)) is not int or words[address] != expected:
            raise ValueError(f"unsupported Retry instruction at {address:#x}")


def render(c, words):
    validate_guards(c, words)
    lines = [
        ".set noreorder",
        ".set noat",
        '.section .text,"ax",@progbits',
        ".balign 16",
        ".globl hook_retry",
        "hook_retry:",
        "sq $sp, -32($sp)",
        f"addiu $sp, $sp, -{PRE_FRAME}",
        f"sq $ra, {PRE_RA}($sp)",
        "jal original_scr_run",
        "nop",
        f"addiu $sp, $sp, -{POST_FRAME}",
    ]
    lines += _capture()
    lines += [
        f"lq $k0, {POST_FRAME + PRE_RA}($sp)",
        f"sq $k0, {OUTER_RA}($sp)",
        f"lq $k0, {POST_FRAME + PRE_SP}($sp)",
        f"sq $k0, {OUTER_SP}($sp)",
    ]
    lines += _load("$t0", "state")
    lines += ["lw $t1, 0($t0)", "bne $t1, $zero, done", "nop"]
    lines += _load("$a0", "context")
    lines += ["jal should_retry", "nop", "beq $v0, $zero, done", "nop"]
    # Do not retain t0 across the callback: even GP and all argument/temp lanes
    # may have been clobbered. Never turn a concurrent/errant Quit into Retry.
    lines += _load("$t0", "state")
    lines += [
        "lw $t1, 0($t0)",
        "bne $t1, $zero, done",
        "nop",
        "addiu $t1, $zero, 1",
        "sw $t1, 0($t0)",
    ]
    lines += _load("$a0", "context")
    lines += ["jal retry_selected", "nop", "done:"]
    lines += _restore()
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    """Return linked payload and one UNAPPLIED JAL WordPatch; never target I/O."""
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler name")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-retry-") as folder:
        source, output = Path(folder) / "hook.s", Path(folder) / "hook.o"
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
                name: getattr(c, name)
                for name in (
                    "original_scr_run",
                    "state",
                    "context",
                    "should_retry",
                    "retry_selected",
                )
            },
        )
    if any(
        p.address < c.code or p.address + len(p.data) > c.code + CODE_SIZE
        for p in linked.payloads
    ):
        raise ValueError("wrapper exceeds reserved code extent")
    return Build(
        assembly,
        linked,
        (WordPatch(c.call_site, c.expected_call, _jal(linked.exports["hook_retry"])),),
    )
