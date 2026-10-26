"""Read-only occupied/pending mount gate, specialized by a reviewed source contract.

No installation, target I/O, reservation or ownership publication occurs here.
The two volatile result registers MUST be proven dead at the selected entry by
the caller's source review, including every original fallthrough path. Callback
values are identities in a request, not functions called by this gate.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

RAM_END = 0x2000000
TYPE_OFFSET = 8
CHARACTER_TYPE = 9  # GetCharacterClass reads this BYTE, not adjacent header flags.
RELATION_OFFSET = 0x9F0
CONTROL_OFFSET = 0x1220
MOUNTED_OFFSET = 0xD98
ROUTES = ((0x150, 0x1B4), (0xF80, 0xFCC), (0x1000, 0x104C))
MOUNT_KINDS = (1, 2, 3, 4, 5, 8, 9, 10)


def _uint(value, bits=32):
    return type(value) is int and 0 <= value < 1 << bits


def _span(address, size, alignment=4):
    return (
        type(address) is int
        and type(size) is int
        and address >= 0x1000
        and size > 0
        and address % alignment == 0
        and address + size <= RAM_END
    )


@dataclass(frozen=True)
class Guard:
    address: int
    expected: int
    width: int = 4

    def __post_init__(self):
        if (
            type(self.width) is not int
            or self.width not in (1, 4)
            or not _span(self.address, self.width, self.width)
            or not _uint(self.expected, self.width * 8)
        ):
            raise ValueError(
                "guard requires aligned physical address and byte/word value"
            )


@dataclass(frozen=True)
class SourceContract:
    """Attestations from source review, not facts inferred from machine addresses.

    The reviewed entry accepts a0=request on SP, a1=registered actor. v0/v1 are
    dead on fallthrough, and returning zero without the prologue is a safe reject.
    Each of the three callback identities selects its corresponding ROUTES entry.
    No callback is invoked here; all other GPR lanes and special/FP state survive.
    """

    review: str
    dead_registers: tuple[str, ...]
    request_on_stack: bool
    zero_rejects: bool
    callback_routes_reviewed: bool

    def __post_init__(self):
        if (
            not isinstance(self.review, str)
            or not self.review.strip()
            or self.dead_registers != ("v0", "v1")
            or self.request_on_stack is not True
            or self.zero_rejects is not True
            or self.callback_routes_reviewed is not True
        ):
            raise ValueError(
                "explicit source-specific entry/dead-register review required"
            )


@dataclass(frozen=True)
class Config:
    entry: int
    native_size: int
    prologue: tuple[int, int]
    caller_return: int
    callbacks: tuple[int, int, int]
    code: int
    code_size: int
    arm: int
    players: tuple[int, int]
    horse: int
    pending_owner: int
    pending_committed: int
    registration: tuple[Guard, Guard, Guard]
    generation: tuple[Guard, ...]
    source_guards: tuple[Guard, ...]
    lifetime_guards: tuple[Guard, ...]
    contract: SourceContract

    def __post_init__(self):
        if not isinstance(self.contract, SourceContract):
            raise ValueError("source contract required")
        if any(
            type(v) is not tuple for v in (self.players, self.callbacks, self.prologue)
        ):
            raise ValueError("immutable player/callback/prologue tuples required")
        if not _span(self.code, self.code_size, 16) or self.code_size % 16:
            raise ValueError("aligned reserved code extent required")
        if not _span(self.entry, self.native_size) or self.native_size < 12 or self.native_size % 4:
            raise ValueError("reviewed native extent must include the continuation")
        for address in (
            self.entry,
            self.caller_return,
            self.arm,
            self.pending_owner,
            self.pending_committed,
        ):
            if not _span(address, 8 if address == self.entry else 4):
                raise ValueError("invalid external address")
        if len(self.players) != 2 or len(set((*self.players, self.horse))) != 3:
            raise ValueError("two distinct players and one horse required")
        if any(
            not _span(a, CONTROL_OFFSET + 4, 16) for a in (*self.players, self.horse)
        ):
            raise ValueError("invalid actor extent")
        if (
            len(self.callbacks) != 3
            or len(set(self.callbacks)) != 3
            or any(not _span(a, 4) for a in self.callbacks)
        ):
            raise ValueError("three distinct aligned callback identities required")
        # Only this small, transparent prologue shape can be replayed. No copied
        # function body is accepted. Register/offset/frame are supplied by review.
        if (
            len(self.prologue) != 2
            or any(not _uint(w) for w in self.prologue)
            or self.prologue[0] >> 16 != 0x27BD
            or self.prologue[1] >> 26 != 63
            or (self.prologue[1] >> 21) & 31 != 29
        ):
            raise ValueError("expected addiu sp,sp,-frame; sd reg,offset(sp)")
        frame = 0x10000 - (self.prologue[0] & 0xFFFF)
        offset = self.prologue[1] & 0xFFFF
        saved = (self.prologue[1] >> 16) & 31
        if (
            frame > 0x8000
            or frame % 8
            or offset % 8
            or offset + 8 > frame
            or saved in (2, 3, 29)
        ):
            raise ValueError("unsafe replayed frame/store")
        groups = (
            self.registration,
            self.generation,
            self.source_guards,
            self.lifetime_guards,
        )
        if any(
            not isinstance(g, tuple) or any(not isinstance(x, Guard) for x in g)
            for g in groups
        ):
            raise ValueError("explicit immutable guard records required")
        if len(self.registration) != 3 or any(
            g.width != 4 or g.expected != a
            for g, a in zip(self.registration, (*self.players, self.horse))
        ):
            raise ValueError("registration guards must attest P1/P2/horse in order")
        if not self.generation or any(
            g.width != 4 or not g.expected for g in self.generation
        ):
            raise ValueError("nonzero current generation authority guards required")
        if not self.source_guards or any(g.width != 4 for g in self.source_guards):
            raise ValueError("reviewed native source word guards required")
        if not self.lifetime_guards:
            raise ValueError("actor/control lifetime guards required")
        guards = guard_expectations(self)
        for i, g in enumerate(guards):
            if any(
                g.address < h.address + h.width and h.address < g.address + g.width
                for h in guards[:i]
            ):
                raise ValueError("overlapping guard records")
        # Nothing read or executed may alias writable placement. The arm is the
        # only data placement, read-only to the gate; its initial payload is zero.
        spans = [
            (self.code, self.code_size),
            (self.arm, 4),
            (self.entry, self.native_size),
            (self.pending_owner, 4),
            (self.pending_committed, 4),
        ]
        spans += [(a, CONTROL_OFFSET + 4) for a in (*self.players, self.horse)]
        for i, (a, n) in enumerate(spans):
            if any(a < b + m and b < a + n for b, m in spans[:i]):
                raise ValueError("owned/native/actor/pending extents overlap")
        for g in guards:
            if any(g.address < a + n and a < g.address + g.width for a, n in spans[:2]):
                raise ValueError("guard overlaps code/arm placement")
        for a in (*self.callbacks, self.caller_return):
            if any(b <= a < b + n for b, n in spans):
                raise ValueError("callback/caller overlaps data or patched entry")


def guard_expectations(c):
    """Width-explicit records; caller must never widen byte guards to words."""
    return (
        *c.registration,
        *c.generation,
        *c.source_guards,
        *c.lifetime_guards,
        *(Guard(a + TYPE_OFFSET, CHARACTER_TYPE, 1) for a in (*c.players, c.horse)),
        Guard(c.entry, c.prologue[0]),
        Guard(c.entry + 4, c.prologue[1]),
    )


def validate_guards(c, values):
    """values maps addresses to values read at EXACTLY the declared width."""
    for g in guard_expectations(c):
        if type(values.get(g.address)) is not int or values[g.address] != g.expected:
            raise ValueError(f"unsupported mount source/lifetime at {g.address:#x}")


def _load(register, value):
    return [
        f"lui {register}, {value >> 16}",
        f"ori {register}, {register}, {value & 0xFFFF}",
    ]


def render(c, values):
    validate_guards(c, values)
    lines = [
        ".set noreorder",
        ".set noat",
        '.section .text,"ax",@progbits',
        ".balign 16",
        ".globl occupied_gate",
        "occupied_gate:",
    ]

    def compare(address, expected, width=4):
        lines.extend(_load("$v0", address))
        lines.append(f"{'lbu' if width == 1 else 'lw'} $v1, 0($v0)")
        lines.extend(_load("$v0", expected))
        lines.extend(["bne $v0, $v1, pass_original", "nop"])

    compare(c.arm, 1)
    lines += _load("$v0", c.caller_return)
    lines += [
        "bne $ra, $v0, pass_original",
        "nop",
        "bne $a0, $sp, pass_original",
        "nop",
        "sltiu $v1, $a0, 4096",
        "bne $v1, $zero, pass_original",
        "nop",
    ]
    lines += _load("$v0", RAM_END - 0x2C)
    lines += ["sltu $v1, $v0, $a0", "bne $v1, $zero, pass_original", "nop"]
    # Entry words are pre-install guards, replaced by the entry jump and NOP.
    # Rechecking the original prologue at runtime would always disable the gate.
    for g in guard_expectations(c)[:-2]:
        compare(g.address, g.expected, g.width)
    lines += _load("$v0", c.players[0])
    lines += ["beq $a1, $v0, actor_ok", "nop"]
    lines += _load("$v0", c.players[1])
    lines += [
        "bne $a1, $v0, pass_original",
        "nop",
        "actor_ok:",
        "lw $v1, 8($a0)",
        "beq $v1, $zero, pass_original",
        "nop",
        "lw $v1, 32($a0)",
    ]
    for i, callback in enumerate(c.callbacks):
        lines += _load("$v0", callback)
        lines += [f"beq $v1, $v0, route_{i}", "nop"]
    lines += ["j pass_original", "nop"]
    for i, (obj, valid) in enumerate(ROUTES):
        lines += [
            f"route_{i}:",
            f"lw $v1, {valid}($a1)",
            "beq $v1, $zero, pass_original",
            "nop",
            f"lw $v1, {obj + 48}($a1)",
        ]
        for kind in MOUNT_KINDS:
            lines += [f"addiu $v0, $zero, {kind}", f"beq $v0, $v1, object_{i}", "nop"]
        lines += ["j pass_original", "nop", f"object_{i}:", f"lw $v1, {obj}($a1)"]
        lines += _load("$v0", c.horse)
        lines += ["bne $v0, $v1, pass_original", "nop", "j occupancy", "nop"]
    lines += ["occupancy:"] + _load("$v0", c.horse)
    lines += [f"lw $v1, {RELATION_OFFSET}($v0)", "beq $v1, $a1, pending_check", "nop"]
    for actor in c.players:
        lines += _load("$v0", actor) + ["beq $v1, $v0, deny", "nop"]
    lines += _load("$v0", c.horse)
    lines += ["bne $v1, $v0, pass_original", "nop", "pending_check:"]
    lines += _load("$v0", c.pending_owner)
    lines += [
        "lw $v1, 0($v0)",
        "beq $v1, $zero, pass_original",
        "nop",
        "beq $v1, $a1, pass_original",
        "nop",
    ]
    lines += _load("$v0", c.players[0]) + ["beq $v1, $v0, pending_known", "nop"]
    lines += _load("$v0", c.players[1]) + [
        "bne $v1, $v0, pass_original",
        "nop",
        "pending_known:",
    ]
    lines += _load("$v0", c.pending_committed)
    lines += ["lw $v0, 0($v0)", "beq $v0, $zero, deny", "nop"]
    # Committed is a nonzero flag, not an actor pointer. Reclamation still
    # requires the horse's native relation to be idle (self-controlled).
    lines += _load("$v0", c.horse)
    lines += [f"lw $v1, {RELATION_OFFSET}($v0)", "bne $v0, $v1, deny", "nop"]
    lines += _load("$v0", c.pending_owner)
    lines += [
        "lw $v1, 0($v0)",
        f"lw $v0, {CONTROL_OFFSET}($v1)",
        "beq $v0, $zero, deny",
        "nop",
        f"lw $v0, {MOUNTED_OFFSET}($v0)",
        "bne $v0, $zero, deny",
        "nop",
        "j pass_original",
        "nop",
        "deny:",
        "jr $ra",
        "daddu $v0, $zero, $zero",
        "pass_original:",
        f".word {c.prologue[0]}",
        f".word {c.prologue[1]}",
        f"j {c.entry + 8}",
        "nop",
    ]
    size = sum(not x.startswith(".") and not x.endswith(":") for x in lines) * 4 + 8
    if size > min(c.code_size, 0x1FFFC):
        raise ValueError("gate exceeds reserved code extent or branch reach")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(c, values, *, assembler=None, objcopy=None):
    """Emit unapplied entry patches and payload; arm initialization is DISABLED.

    Placement/lifetime authority and exclusive installation are caller duties.
    """
    assembly = render(c, values)
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("explicit objcopy required for nonstandard assembler")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-mount-") as folder:
        source, output = Path(folder) / "gate.s", Path(folder) / "gate.o"
        source.write_text(
            assembly + '.section .mount_arm,"aw",@progbits\n.balign 4\n'
            ".globl occupied_arm\noccupied_arm:\n.word 0\n"
        )
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
            {".text": c.code, ".data": c.code, ".bss": c.code, ".mount_arm": c.arm},
            {},
        )
    for p in linked.payloads:
        lo, hi = (
            (c.code, c.code + c.code_size)
            if p.section in (".text", ".data", ".bss")
            else (c.arm, c.arm + 4)
        )
        if not lo <= p.address <= p.address + len(p.data) <= hi:
            raise ValueError("payload exceeds reserved placement")
    jump = 0x08000000 | (linked.exports["occupied_gate"] >> 2)
    return Build(
        assembly,
        linked,
        (
            WordPatch(c.entry, c.prologue[0], jump),
            WordPatch(c.entry + 4, c.prologue[1], 0),
        ),
    )
