"""Offline R5900 wrapper for completion of the actual render call.

The configured actual_render is the real render entry, NOT the old activation
stub decoded from expected_call. Trusted ranges must be externally verified;
address checks are not code identity checks. No game/ISO access or installation
is performed here. The caller owns and initializes the external counter block
(low uint32, high uint32, sticky fault uint32, padding); this module deliberately
defines no counter BSS and never resets a counter or clears its fault.

There is one EE producer and one EE consumer at a serialized frame boundary.
The two word stores are NOT an atomic 64-bit publication to a host reader.
Completion includes normal and fallback returns regardless of v0. A coroutine
yield is not completion: the increment runs only when actual_render returns.
No simulation/FPS state is touched and there are no calls after that increment.
By default this proves CPU return only, NOT GPU completion or safe resource
lifetime: fallback can return with GPU work still outstanding. For a qualified
GPU drain, configure both fence_target and fence_state. The fence receives
a0=fence_state after render returns; zero advances the counter, nonzero latches
fault without advancing. GPU lifetime safety still depends on the external
drain's independently qualified contract, not just its address or return value.

All eight EABI register arguments reach the callee unchanged after the verified
original delay slot. The 96-byte pre-call frame has 64 outgoing home bytes,
original full-width SP at 64 and RA at 80. Once the callee returns, its home area
holds full-width post-call t0-t3 while integer-only bookkeeping runs. All other
post-call state (including GP, v0/v1, FPRs, HI/LO and SA) is untouched; original
SP/RA are restored. The callee must obey stack discipline; the additional stack
space and the external entry's ABI still require independent qualification.
The optional fence allocates an additional post-call frame only AFTER render
returns and preserves all observable post-render GPR/HI/LO/SA/FPU/FCSR state.
The fence must obey stack discipline, handle its own GP, and not modify FPACC
or VU state (which this wrapper cannot save). Reserve
Config.code_size bytes of code: the default remains CODE_SIZE, while the fence
path requires FENCED_CODE_SIZE. Counter and fence state initialization remain
external; fence_state validates a pointer, not the unknown full state extent.

Optional target_stack=(base, size) and stack_state bind a caller-owned persistent
16--64 KiB render stack and a separate 16-byte state block. The state words are
busy, sticky fault, optional externally measured highwater and reserved; only
busy/fault are written here. Initialize busy externally before first use. No
canary scan, stack allocation, zeroing or highwater measurement occurs here.
Reserve STACKED_CODE_SIZE code bytes in this mode. The original stack uses only
the 96-byte outer frame; the renderer and any fence use the private allocation
from the start of their calls. The renderer still receives all eight arguments
and its original GP unchanged. On return, post-render t0/t1 are bridged through
the outer frame so busy is cleared only after restoring the original full SP.

The renderer and fence may yield through native WaitSema only with the original
serialized, nonreentrant scheduler. This persistent stack is not a command
stack and must not be reclaimed while busy. Nested entry latches both stack and
counter faults, leaves busy set for its owner, and returns without rendering;
that fail-closed return does NOT simulate a working render frame. The wrapper
does not establish general concurrent/reentrant safety or detect stack overflow.

Optional prepare_target/prepare_context run prepare(context) on the acquired
private stack before any actual render call. Both require target_stack. A
temporary private frame preserves all incoming GPR/FPU/HI/LO/SA/FCSR state and
is popped before rendering, so renderer recursion has the same stack headroom.
The callback may yield under the same scheduler/ownership contract as the
renderer; its context must remain valid throughout that yield. It must handle
its own GP and leave FPACC/VU state untouched. Context validation covers the
pointer word, not an unknown full context extent; ownership is caller-attested.
Zero means prepared. Nonzero skips render/fence and counter advancement,
latches both faults, releases only this invocation's acquired stack, and
returns low 64 bits of v0 = 1 (upper 64 bits retained from incoming v0).
Every other incoming register and original full-width SP/RA is restored.
Preparation failure is not a simulated successful render frame.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

from .hooks import (
    FRAME as POST_FRAME,
)
from .hooks import (
    GPRS,
    OUTER_RA,
    OUTER_SP,
    _address,
    _capture,
    _jal,
    _load,
    _restore,
)

CODE_SIZE = 0x200
FENCED_CODE_SIZE = 0x400
STACKED_CODE_SIZE = 0x800
COUNTER_SIZE = 16
COUNTER_LOW, COUNTER_HIGH, COUNTER_FAULT = 0, 4, 8
PRE_FRAME, PRE_SP, PRE_RA = 96, 64, 80
STACK_STATE_SIZE = 16
STACK_BUSY, STACK_FAULT, STACK_HIGHWATER = 0, 4, 8


@dataclass(frozen=True)
class Config:
    call_site: int
    expected_call: int
    expected_delay: int
    actual_render: int
    code: int
    counter: int
    trusted_code: tuple[tuple[int, int], ...]
    fence_target: int | None = None
    fence_state: int | None = None
    target_stack: tuple[int, int] | None = None
    stack_state: int | None = None
    prepare_target: int | None = None
    prepare_context: int | None = None

    @property
    def code_size(self):
        if self.target_stack is not None:
            return STACKED_CODE_SIZE
        return CODE_SIZE if self.fence_target is None else FENCED_CODE_SIZE

    def __post_init__(self):
        if not _address(self.call_site) or not _address(self.call_site + 4):
            raise ValueError("call and delay must be physical EE addresses")
        if not _address(self.code, 16) or not _address(self.counter, 16):
            raise ValueError("code/counter must be aligned physical EE addresses")
        if (
            type(self.expected_call) is not int
            or not 0 <= self.expected_call <= 0xFFFFFFFF
            or self.expected_call >> 26 != 3
        ):
            raise ValueError("expected_call must be the exact old JAL word")
        if (
            type(self.expected_delay) is not int
            or not 0 <= self.expected_delay <= 0xFFFFFFFF
        ):
            raise ValueError("expected_delay must be an exact uint32 word")
        if (self.fence_target is None) != (self.fence_state is None):
            raise ValueError("fence_target and fence_state must be configured together")
        if self.fence_state is not None and not _address(self.fence_state):
            raise ValueError("fence_state must be an aligned physical EE pointer")
        if (self.prepare_target is None) != (self.prepare_context is None):
            raise ValueError(
                "prepare_target and prepare_context must be configured together"
            )
        if self.prepare_target is not None:
            if self.target_stack is None:
                raise ValueError("prepare requires an owned private target_stack")
            if not _address(self.prepare_context):
                raise ValueError(
                    "prepare_context must be an aligned physical EE pointer"
                )
        spans = [(self.code, self.code_size), (self.counter, COUNTER_SIZE)]
        for base, size in self.trusted_code:
            if not _address(base, 4) or type(size) is not int or size <= 0 or size % 4:
                raise ValueError("invalid trusted code extent")
            spans.append((base, size))
        for i, (base, size) in enumerate(spans):
            if base + size > 0x2000000:
                raise ValueError("extent exceeds physical EE RAM")
            if any(base < b + n and b < base + size for b, n in spans[:i]):
                raise ValueError("code/counter/trusted extents overlap")
        old_target = ((self.call_site + 4) & 0xF0000000) | (
            (self.expected_call & 0x3FFFFFF) << 2
        )
        targets = (old_target, self.actual_render)
        if self.fence_target is not None:
            targets += (self.fence_target,)
        if self.prepare_target is not None:
            targets += (self.prepare_target,)
        for target in targets:
            if not _address(target) or not any(
                b <= target and target + 4 <= b + n for b, n in self.trusted_code
            ):
                raise ValueError(
                    "render, fence and prepare targets must be trusted physical code"
                )
        if self.fence_target is not None:
            if (self.code + self.code_size) >> 28 != self.fence_target >> 28:
                raise ValueError("fence outside wrapper JAL segment")
            if (
                any(
                    self.fence_state < b + n and b < self.fence_state + 4
                    for b, n in spans
                )
                or self.call_site <= self.fence_state < self.call_site + 8
            ):
                raise ValueError("fence state overlaps code/counter/call site")
        if (self.code + 4) >> 28 != self.actual_render >> 28:
            raise ValueError("actual render outside wrapper JAL segment")
        if (self.call_site + 4) >> 28 != self.code >> 28:
            raise ValueError("wrapper outside call-site JAL segment")
        # The call site may be in a trusted executable extent, but it must not
        # overwrite the actual or old entry, or overlap owned code/counter data.
        if any(self.call_site < b + n and b < self.call_site + 8 for b, n in spans[:2]):
            raise ValueError("call/delay overlaps owned memory")
        if any(self.call_site <= t < self.call_site + 8 for t in targets):
            raise ValueError("call/delay overlaps a render target")
        if (self.target_stack is None) != (self.stack_state is None):
            raise ValueError("target_stack and stack_state must be configured together")
        if self.target_stack is not None:
            if not isinstance(self.target_stack, tuple) or len(self.target_stack) != 2:
                raise ValueError("target_stack must be a (base, size) tuple")
            base, size = self.target_stack
            if (
                not _address(base, 16)
                or type(size) is not int
                or not 0x4000 <= size <= 0x10000
                or size % 16
                or base + size > 0x2000000
            ):
                raise ValueError(
                    "target stack must be aligned physical 16--64 KiB memory"
                )
            if (
                not _address(self.stack_state, 16)
                or self.stack_state + STACK_STATE_SIZE > 0x2000000
            ):
                raise ValueError("stack_state must be an aligned owned 16-byte block")
            excluded = spans + [(self.call_site, 8)]
            if self.fence_state is not None:
                excluded.append((self.fence_state, 4))
            for start, extent in ((base, size), (self.stack_state, STACK_STATE_SIZE)):
                if any(start < b + n and b < start + extent for b, n in excluded):
                    raise ValueError(
                        "target stack/state overlaps code, counter or context"
                    )
                excluded.append((start, extent))
            if self.prepare_target is not None:
                if (self.code + self.code_size) >> 28 != self.prepare_target >> 28:
                    raise ValueError("prepare outside wrapper JAL segment")
                if any(
                    self.prepare_context < b + n and b < self.prepare_context + 4
                    for b, n in excluded
                ):
                    raise ValueError(
                        "prepare context overlaps code, counter, stack or context"
                    )


def guard_expectations(c):
    return {c.call_site: c.expected_call, c.call_site + 4: c.expected_delay}


def validate_guards(c, words):
    for address, expected in guard_expectations(c).items():
        if type(words.get(address)) is not int or words[address] != expected:
            raise ValueError(f"unsupported render instruction at {address:#x}")


def _stack_entry():
    """Save only the scratch argument registers; leave a0-a3/t2-t3/GP alone."""
    lines = ["sq $t0, 0($sp)", "sq $t1, 16($sp)"]
    lines += _load("$t0", "stack_state")
    lines += [
        f"lw $t1, {STACK_BUSY}($t0)",
        "bne $t1, $zero, stack_busy",
        "nop",
        "addiu $t1, $zero, 1",
        f"sw $t1, {STACK_BUSY}($t0)",
    ]
    lines += _load("$t1", "target_stack_frame")
    lines += [
        f"lq $t0, {PRE_SP}($sp)",
        f"sq $t0, {PRE_SP}($t1)",
        f"lq $t0, {PRE_RA}($sp)",
        f"sq $t0, {PRE_RA}($t1)",
        "lq $t0, 0($sp)",
        "sq $t0, 0($t1)",
        "lq $t0, 16($sp)",
        "sq $t0, 16($t1)",
    ]
    lines += _load("$sp", "target_stack_frame")
    return lines + ["lq $t0, 0($sp)", "lq $t1, 16($sp)"]


def _stack_return(fenced, *, prepare_failed=False):
    # Use the original outer frame as the final scratch bridge, then leave the
    # private stack BEFORE releasing busy. Every other post-render register is
    # restored untouched; the last two loads recover full 128-bit t0/t1.
    original_sp = OUTER_SP if fenced else PRE_SP
    post_t0, post_t1 = (GPRS + 8 * 16, GPRS + 9 * 16) if fenced else (0, 16)
    lines = [
        f"lq $t0, {original_sp}($sp)",
        f"lq $t1, {post_t0}($sp)",
        f"sq $t1, -{PRE_FRAME}($t0)",
        f"lq $t1, {post_t1}($sp)",
        f"sq $t1, {16 - PRE_FRAME}($t0)",
    ]
    if fenced:
        lines += _restore()[:-2]  # restore through original SP, but not jr/nop
    else:
        lines += [
            "lq $t2, 32($sp)",
            "lq $t3, 48($sp)",
            f"lq $ra, {PRE_RA}($sp)",
            f"lq $sp, {PRE_SP}($sp)",
        ]
    lines += _load("$t0", "stack_state")
    lines += [
        f"sw $zero, {STACK_BUSY}($t0)",
        f"lq $t1, {16 - PRE_FRAME}($sp)",
        f"lq $t0, -{PRE_FRAME}($sp)",
    ]
    if prepare_failed:
        lines.append("addiu $v0, $zero, 1")
    return lines + ["jr $ra", "nop"]


def _prepare():
    # OUTER_SP is the full private SP for the success path, not original SP.
    # Save it before allocation; _capture does not itself capture SP.
    lines = ["sq $sp, -16($sp)", f"addiu $sp, $sp, -{POST_FRAME}"]
    lines += _capture()
    lines += [
        f"lq $k0, {POST_FRAME + PRE_RA}($sp)",
        f"sq $k0, {OUTER_RA}($sp)",
    ]
    lines += _load("$a0", "prepare_context")
    lines += ["jal prepare_target", "nop", "bne $v0, $zero, prepare_failed", "nop"]
    # Restore incoming state and private pre-call SP, then fall through to the
    # actual renderer without keeping this frame on its recursive call stack.
    return lines + _restore()[:-2]


def _prepare_failed():
    lines = ["prepare_failed:"]
    lines += _load("$t0", "counter")
    lines += ["addiu $t1, $zero, 1", f"sw $t1, {COUNTER_FAULT}($t0)"]
    lines += _load("$t0", "stack_state")
    lines += [
        f"sw $t1, {STACK_FAULT}($t0)",
        # Switch the saved return SP from private to original before using the
        # same full-state restore/ownership release as a completed frame.
        f"lq $t0, {POST_FRAME + PRE_SP}($sp)",
        f"sq $t0, {OUTER_SP}($sp)",
    ]
    return lines + _stack_return(True, prepare_failed=True)


def _stack_rejected():
    lines = [
        "stack_busy:",
        "addiu $t1, $zero, 1",
        f"sw $t1, {STACK_FAULT}($t0)",
    ]
    lines += _load("$t0", "counter")
    return lines + [
        f"sw $t1, {COUNTER_FAULT}($t0)",
        "lq $t0, 0($sp)",
        "lq $t1, 16($sp)",
        f"lq $ra, {PRE_RA}($sp)",
        f"lq $sp, {PRE_SP}($sp)",
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
        ".globl hook_render",
        "hook_render:",
        "sq $sp, -32($sp)",
        f"addiu $sp, $sp, -{PRE_FRAME}",
        f"sq $ra, {PRE_RA}($sp)",
    ]
    if c.target_stack is not None:
        lines += _stack_entry()
    if c.prepare_target is not None:
        lines += _prepare()
    lines += ["jal actual_render", "nop"]
    if c.fence_target is None:
        lines += [f"sq $t{i}, {i * 16}($sp)" for i in range(4)]
    else:
        lines += [f"addiu $sp, $sp, -{POST_FRAME}"]
        lines += _capture()
        lines += [
            f"lq $k0, {POST_FRAME + PRE_RA}($sp)",
            f"sq $k0, {OUTER_RA}($sp)",
            f"lq $k0, {POST_FRAME + PRE_SP}($sp)",
            f"sq $k0, {OUTER_SP}($sp)",
        ]
        lines += _load("$a0", "fence_state")
        lines += [
            "jal fence_target",
            "nop",
            "beq $v0, $zero, fence_succeeded",
            "nop",
        ]
        lines += _load("$t0", "counter")
        lines += [
            "addiu $t3, $zero, 1",
            f"sw $t3, {COUNTER_FAULT}($t0)",
            "beq $zero, $zero, completed",
            "nop",
            "fence_succeeded:",
        ]
    lines += [
        "lui $t0, %hi(counter)",
        "addiu $t0, $t0, %lo(counter)",
        f"lw $t1, {COUNTER_LOW}($t0)",
        f"lw $t2, {COUNTER_HIGH}($t0)",
        "addiu $t3, $zero, -1",
        "bne $t1, $t3, increment_low",
        "nop",
        "bne $t2, $t3, carry_high",
        "nop",
        "addiu $t3, $zero, 1",
        f"sw $t3, {COUNTER_FAULT}($t0)",
        "beq $zero, $zero, completed",
        "nop",
        "carry_high:",
        "addiu $t2, $t2, 1",
        f"sw $t2, {COUNTER_HIGH}($t0)",
        "increment_low:",
        "addiu $t1, $t1, 1",
        f"sw $t1, {COUNTER_LOW}($t0)",
        "completed:",
    ]
    if c.target_stack is not None:
        lines += _stack_return(c.fence_target is not None)
        lines += _stack_rejected()
        if c.prepare_target is not None:
            lines += _prepare_failed()
    elif c.fence_target is None:
        lines += [f"lq $t{i}, {i * 16}($sp)" for i in range(4)]
        lines += [f"lq $ra, {PRE_RA}($sp)", f"lq $sp, {PRE_SP}($sp)", "jr $ra", "nop"]
    else:
        lines += _restore()
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, words, *, assembler=None, objcopy=None):
    """Assemble/link an offline payload and one unapplied four-byte JAL patch."""
    assembly = render(c, words)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler name")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-render-") as folder:
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
                ".data": c.code + c.code_size - 32,
                ".bss": c.code + c.code_size - 16,
            },
            {
                "actual_render": c.actual_render,
                "counter": c.counter,
                **(
                    {"fence_target": c.fence_target, "fence_state": c.fence_state}
                    if c.fence_target is not None
                    else {}
                ),
                **(
                    {
                        "target_stack_frame": sum(c.target_stack) - PRE_FRAME,
                        "stack_state": c.stack_state,
                    }
                    if c.target_stack is not None
                    else {}
                ),
                **(
                    {
                        "prepare_target": c.prepare_target,
                        "prepare_context": c.prepare_context,
                    }
                    if c.prepare_target is not None
                    else {}
                ),
            },
        )
    if any(
        p.address < c.code or p.address + len(p.data) > c.code + c.code_size
        for p in linked.payloads
    ):
        raise ValueError("wrapper exceeds owned code extent")
    target = linked.exports["hook_render"]
    if (c.call_site + 4) >> 28 != target >> 28:
        raise ValueError("replacement outside JAL segment")
    return Build(
        assembly, linked, (WordPatch(c.call_site, c.expected_call, _jal(target)),)
    )
