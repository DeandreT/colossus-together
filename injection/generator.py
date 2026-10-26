"""Render only our assembly and optionally assemble/link it offline.

Addresses are loaded disassembly-listing origins; actual XFF .text starts 0x38
bytes later for this revision. Guard words
are small validated excerpts of the NTSC-U disassembly, not binary payloads.
"""

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch

from .records import CAPACITY, RING_SIZE, STATE_SIZE

# The extra guards establish that s0 is saved then overwritten before use.
SITES = {
    "script_char": (
        "m",
        0x832D8,
        {
            0: 0x27BDFCF0,
            4: 0x0000702D,
            0x14: 0xFFB002C0,
            0x18: 0xFFB402E0,
            0x24: 0x00C0802D,
        },
    ),
    "alias_layout": (
        "m",
        0x82FA0,
        {0: 0x27BDFE90, 4: 0x3C020003, 8: 0xFFB00120, 12: 0x00A0802D},
    ),
    "delete_request": ("k", 0x1ABE8, {0: 0x27BDFFD0, 4: 0xFFB00000, 8: 0x0080802D}),
}
FREE_CALL_OFFSET = 0x1975C
IOS_FREE_OFFSET = 0x39C8


def _sites(config):
    return tuple(
        (name, site)
        for name, site in SITES.items()
        if name != "delete_request" or config.capture_delete_requests
    )


def guard_expectations(config):
    """Loaded words and masks, including the relocated local iosFree JAL."""
    guards = {
        getattr(config, module) + offset + delta: (word, 0xFFFFFFFF)
        for _, (module, offset, site_guards) in _sites(config)
        for delta, word in site_guards.items()
    }
    guards.update(
        {
            config.k + FREE_CALL_OFFSET - 4: (0x8E240000, 0xFFFFFFFF),
            config.k + FREE_CALL_OFFSET: (
                0x0C000000 | ((config.k + IOS_FREE_OFFSET) >> 2),
                0xFFFFFFFF,
            ),
            config.k + FREE_CALL_OFFSET + 4: (0x0200882D, 0xFFFFFFFF),
            config.k + IOS_FREE_OFFSET: (0x27BDFFE0, 0xFFFFFFFF),
            config.k + IOS_FREE_OFFSET + 4: (0xFFB00000, 0xFFFFFFFF),
            # Relocated LUI immediate varies; opcode and destination must not.
            config.k + IOS_FREE_OFFSET + 8: (0x3C100000, 0xFFFF0000),
        }
    )
    return guards


@dataclass(frozen=True)
class Config:
    g: int
    m: int
    k: int
    code: int
    ring: int
    state: int
    capture_delete_requests: bool = True
    free_watch: int | None = None
    free_watch_capacity: int = 64

    def __post_init__(self):
        if type(self.capture_delete_requests) is not bool:
            raise ValueError("capture_delete_requests must be a Boolean")
        for address in (self.g, self.m, self.k, self.code, self.ring, self.state):
            if (
                type(address) is not int
                or not 0x80000 <= address < 0x2000000
                or address % 16
            ):
                raise ValueError("addresses must be physical EE RAM, 16-byte aligned")
        spans = [
            (self.ring, self.ring + RING_SIZE),
            (self.state, self.state + STATE_SIZE),
            (self.code, self.code + 0x4000),
        ]
        if (
            type(self.free_watch_capacity) is not int
            or not 1 <= self.free_watch_capacity <= 256
        ):
            raise ValueError("invalid final-free watch capacity")
        if self.free_watch is not None:
            if (
                type(self.free_watch) is not int
                or self.free_watch % 4
                or self.free_watch < 0x80000
            ):
                raise ValueError("invalid final-free watch address")
            spans.append(
                (self.free_watch, self.free_watch + 4 + 4 * self.free_watch_capacity)
            )
        if any(end > 0x2000000 for _, end in spans):
            raise ValueError("helper allocation exceeds EE RAM")
        if any(
            a < d and c < b for i, (a, b) in enumerate(spans) for c, d in spans[i + 1 :]
        ):
            raise ValueError("helper allocations overlap")
        for module, offset, _ in (
            *(site for _, site in _sites(self)),
            ("k", FREE_CALL_OFFSET, {}),
            ("k", IOS_FREE_OFFSET, {}),
        ):
            site = getattr(self, module) + offset
            if site + 0x30 > 0x2000000 or any(
                a < site + 0x30 and site < b for a, b in spans
            ):
                raise ValueError("hook site outside RAM or overlaps helper")
        if any(
            a < address + 4 and address < b
            for address in guard_expectations(self)
            for a, b in spans
        ):
            raise ValueError("instruction guard overlaps helper allocation")


def validate_prologues(config, words):
    """Requires every guard address, never assumes a missing read succeeded."""
    for address, (expected, mask) in guard_expectations(config).items():
        word = words.get(address)
        if (
            type(word) is not int
            or not 0 <= word <= 0xFFFFFFFF
            or word & mask != expected
        ):
            raise ValueError(f"unsupported instruction at {address:#x}")


def _load(register, value):
    return [
        f"lui {register}, 0x{value >> 16:x}",
        f"ori {register}, {register}, 0x{value & 65535:x}",
    ]


def render(config, words):
    validate_prologues(config, words)
    lines = [
        ".set noreorder",
        ".set noat",
        '.section .text,"ax",@progbits',
        ".balign 16",
    ]
    hooks = (*_sites(config), ("final_free_allocation", ("k", FREE_CALL_OFFSET, {})))
    kinds = {
        "script_char": 1,
        "alias_layout": 2,
        "delete_request": 3,
        "final_free_allocation": 4,
    }
    for name, (module, offset, guards) in hooks:
        kind = kinds[name]

        def emit(*text):
            lines.extend(text)

        def branch(instruction):
            emit(instruction, "nop")

        site = getattr(config, module) + offset
        emit(f".globl hook_{name}", f"hook_{name}:")
        if name == "final_free_allocation" and config.free_watch is not None:
            emit(*_load("$t4", config.free_watch), "lw $t5, 0($t4)")
            emit(f"sltiu $t6, $t5, {config.free_watch_capacity + 1}")
            branch(f"beq $t6, $zero, bad_watch_{name}")
            for index in range(config.free_watch_capacity):
                emit(f"sltiu $t6, $t5, {index + 1}")
                branch(f"bne $t6, $zero, unwatched_{name}")
                emit(f"lw $t6, {4 + index * 4}($t4)")
                branch(f"beq $a0, $t6, watched_{name}")
            emit(f"unwatched_{name}:")
            branch(f"b trampoline_{name}")
            emit(f"bad_watch_{name}:", *_load("$t4", config.state))
            branch(f"b lost_{name}")
            emit(f"watched_{name}:")
        emit(*_load("$t4", config.state))
        emit("lw $t5, 16($t4)", "lw $t6, 20($t4)", "lw $t7, 24($t4)")
        branch(f"bne $t7, $zero, lost_{name}")
        emit("addiu $t7, $zero, -1")
        branch(f"beq $t5, $t7, lost_{name}")
        emit("subu $t7, $t5, $t6", f"sltiu $t7, $t7, {CAPACITY}")
        branch(f"beq $t7, $zero, lost_{name}")
        emit("addiu $t6, $t5, 1", "andi $t7, $t5, 63", "sll $t7, $t7, 8")
        emit(*_load("$t8", config.ring), "addu $t8, $t8, $t7")
        # Only bounded, unrolled stores/copies; no allocation or target loops.
        for at in range(0, 256, 16):
            emit(f"sq $zero, {at}($t8)")
        emit(
            "sw $t6, 4($t8)",
            "sync",
            "sw $t6, 16($t4)",
            f"addiu $t7, $zero, {kind}",
            "sw $t7, 8($t8)",
        )
        for i, register in enumerate(("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3")):
            emit(f"sw ${register}, {32 + i * 4}($t8)")
        if name == "delete_request":
            emit("sw $a0, 16($t8)", "sync", "sw $t6, 0($t8)")
            branch(f"b trampoline_{name}")
        elif name == "final_free_allocation":
            emit(
                "sw $a0, 124($t8)",
                "sq $s0, 192($t8)",
                "sq $ra, 208($t8)",
                "daddu $s0, $t8, $zero",
            )
            branch(f"jal trampoline_{name}")
            # Do not inspect a0, s1, the object, or the allocation after free.
            emit(
                "daddu $t8, $s0, $zero",
                "lw $t9, 4($t8)",
                "lq $ra, 208($t8)",
                "lq $s0, 192($t8)",
                "sync",
                "sw $t9, 0($t8)",
            )
            branch("jr $ra")
        else:
            emit("sq $s0, 192($t8)", "sq $ra, 208($t8)")
            # Parameter reads are byte copies: unaligned but valid RAM allowed.
            emit(*_load("$t7", 0x80000), "sltu $t9, $a2, $t7")
            branch(f"bne $t9, $zero, missing_{name}")
            emit(*_load("$t7", 0x2000000 - 0x3C + 1), "sltu $t9, $a2, $t7")
            branch(f"beq $t9, $zero, missing_{name}")
            for at in range(0x3C):
                emit(f"lbu $t7, {at}($a2)", f"sb $t7, {64 + at}($t8)")
            emit("addiu $t7, $zero, 60", "sw $t7, 24($t8)")
            # Assemble a little-endian pointer without requiring a2 alignment.
            emit("lbu $t5, 32($a2)")
            for byte in range(1, 4):
                emit(
                    f"lbu $t7, {32 + byte}($a2)",
                    f"sll $t7, $t7, {8 * byte}",
                    "or $t5, $t5, $t7",
                )
            emit("sw $t5, 20($t8)")
            branch(f"beq $t5, $zero, invoke_{name}")
            emit(*_load("$t7", 0x80000), "sltu $t9, $t5, $t7")
            branch(f"bne $t9, $zero, bad_gp_{name}")
            emit(*_load("$t7", 0x2000000 - 0x40 + 1), "sltu $t9, $t5, $t7")
            branch(f"beq $t9, $zero, bad_gp_{name}")
            for at in range(0x40):
                emit(f"lbu $t7, {at}($t5)", f"sb $t7, {128 + at}($t8)")
            emit("addiu $t7, $zero, 64", "sw $t7, 28($t8)")
            branch(f"b invoke_{name}")
            emit(f"missing_{name}:", "addiu $t7, $zero, 1", "sw $t7, 12($t8)")
            branch(f"b invoke_{name}")
            emit(f"bad_gp_{name}:", "addiu $t7, $zero, 2", "sw $t7, 12($t8)")
            emit(f"invoke_{name}:", "daddu $s0, $t8, $zero")
            # No wrapper frame: original incoming SP/stack arguments unchanged.
            branch(f"jal trampoline_{name}")
            emit("sw $v0, 16($s0)")
            branch(f"beq $v0, $zero, allocation_done_{name}")
            emit("andi $t7, $v0, 3")
            branch(f"bne $t7, $zero, bad_allocation_{name}")
            emit(*_load("$t7", 0x80000), "sltu $t9, $v0, $t7")
            branch(f"bne $t9, $zero, bad_allocation_{name}")
            emit(*_load("$t7", 0x2000000 - 4 + 1), "sltu $t9, $v0, $t7")
            branch(f"beq $t9, $zero, bad_allocation_{name}")
            emit("lw $t7, 0($v0)", "sw $t7, 124($s0)")
            branch(f"b allocation_done_{name}")
            emit(
                f"bad_allocation_{name}:",
                "lw $t7, 12($s0)",
                "ori $t7, $t7, 4",
                "sw $t7, 12($s0)",
            )
            emit(f"allocation_done_{name}:")
            emit(
                "daddu $t8, $s0, $zero",
                "lw $t9, 4($t8)",
                "lq $ra, 208($t8)",
                "lq $s0, 192($t8)",
                "sync",
                "sw $t9, 0($t8)",
            )
            branch("jr $ra")
        emit(f"lost_{name}:", "addiu $t7, $zero, 1", "sw $t7, 24($t4)")
        branch(f"b trampoline_{name}")
        emit(f"trampoline_{name}:")
        if name != "final_free_allocation":
            emit(f".word 0x{guards[0]:08x}", f".word 0x{guards[4]:08x}")
        emit(
            *_load(
                "$t9",
                config.k + IOS_FREE_OFFSET
                if name == "final_free_allocation"
                else site + 8,
            )
        )
        branch("jr $t9")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: object
    patches: tuple[WordPatch, ...]


def build(config, words, *, assembler="mips64r5900el-ps2-elf-as", objcopy=None):
    """Compile a temporary object, use runtime.elf, return bytes and patch plan.

    Does not read/write an emulator, game binary, ISO or SSH connection.
    The caller must independently establish exclusive ownership of placements.
    """
    assembly = render(config, words)
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("supply objcopy when assembler lacks the -as suffix")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-injection-") as folder:
        source, output = Path(folder) / "capture.s", Path(folder) / "capture.o"
        source.write_text(assembly)
        subprocess.run(
            [
                assembler,
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
        # runtime.elf intentionally does not load ABI metadata. Remove its
        # section symbols too, rather than weakening the shared linker.
        subprocess.run(
            [
                objcopy,
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
                ".text": config.code,
                ".data": config.code + 0x3000,
                ".bss": config.code + 0x3100,
            },
        )
    if sum(len(p.data) for p in linked.payloads) > 0x3000:
        raise ValueError("helper exceeds reserved code extent")
    patches = []
    for name, (module, offset, guards) in _sites(config):
        address = getattr(config, module) + offset
        target = linked.exports[f"hook_{name}"]
        if (address + 4) >> 28 != target >> 28:
            raise ValueError("hook outside J instruction region")
        patches.extend(
            (
                WordPatch(address, guards[0], 0x08000000 | (target >> 2)),
                WordPatch(address + 4, guards[4], 0),
            )
        )
    address = config.k + FREE_CALL_OFFSET
    target = linked.exports["hook_final_free_allocation"]
    if (address + 4) >> 28 != target >> 28:
        raise ValueError("free call hook outside JAL instruction region")
    patches.append(
        WordPatch(
            address, guard_expectations(config)[address][0], 0x0C000000 | (target >> 2)
        )
    )
    return Build(assembly, linked, tuple(patches))
