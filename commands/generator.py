"""Generate our own R5900 EABI dispatcher; never read or patch game assets."""

import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import link_object
from runtime.patches import WordPatch
from runtime.pine import check_range

from .protocol import SIZE, u32

CALL_OFFSET = 0xC678
USB_OFFSET = 0xD05F0  # MANAGER text-relative, caller supplies its loaded base.
USB_ENTRY = (0x27BDFFF0, 0xFFB00000)
CODE_SIZE = 0x3000
FRAME = 896
GPRS = (
    "zero",
    "at",
    "v0",
    "v1",
    "a0",
    "a1",
    "a2",
    "a3",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "t8",
    "t9",
    "k0",
    "k1",
    "gp",
    "sp",
    "fp",
    "ra",
)


def physical(address):
    """Accept only EE RAM physical, KSEG0 or KSEG1 aliases; no blind masking."""
    u32(address)
    if address & 0xE0000000 not in (0, 0x80000000, 0xA0000000):
        raise ValueError("unsupported EE segment")
    result = address & 0x1FFFFFFF
    check_range(result, 4, 4)
    if result < 0x80000:
        raise ValueError("address below executable/managed EE RAM")
    return result


@dataclass(frozen=True)
class Target:
    address: int
    gp: int

    def __post_init__(self):
        object.__setattr__(self, "address", physical(self.address))
        object.__setattr__(self, "gp", physical(self.gp))


@dataclass(frozen=True)
class Config:
    gamecore: int
    original_usb: int
    usb_entry: tuple
    delay_word: int
    code: int
    mailbox: int
    executable: tuple
    targets: tuple
    previous_dispatch: int | None = None
    target_stack: tuple[int, int] | None = None
    frame_callback: Target | None = None

    def __post_init__(self):
        # Placements are canonical physical RAM, not unchecked aliases.
        for address in (self.gamecore, self.original_usb, self.code, self.mailbox):
            if physical(address) != address:
                raise ValueError("placements must use physical EE addresses")
        if self.code % 16 or self.mailbox % 16:
            raise ValueError("code and mailbox must be 16-byte aligned")
        object.__setattr__(self, "targets", tuple(self.targets))
        object.__setattr__(self, "usb_entry", tuple(self.usb_entry))
        object.__setattr__(self, "executable", tuple(tuple(r) for r in self.executable))
        if not 1 <= len(self.targets) <= 256 or not all(
            isinstance(t, Target) for t in self.targets
        ):
            raise ValueError("expected 1..256 immutable approved Targets")
        if not 2 <= len(self.usb_entry) <= 4:
            raise ValueError("supply 2..4 independently verified USB entry guard words")
        if self.usb_entry[:2] != USB_ENTRY or self.delay_word != 0:
            raise ValueError("unsupported NTSC-U USB entry/call delay slot")
        for value in (*self.usb_entry, self.delay_word):
            u32(value)
        if not self.executable:
            raise ValueError("explicit executable whitelist required")
        for start, end in self.executable:
            check_range(start, end - start, 4)
            if start < 0x80000 or end <= start or end % 4:
                raise ValueError("invalid executable extent")
        sites = [self.gamecore + CALL_OFFSET, self.original_usb]
        if self.frame_callback is not None:
            if not isinstance(self.frame_callback, Target):
                raise ValueError("frame_callback must be an immutable approved Target")
            if self.target_stack is None:
                raise ValueError("frame_callback requires target_stack")
            sites.append(self.frame_callback.address)
        for address in (*sites, *(t.address for t in self.targets)):
            if not any(
                lo <= address and address + 4 <= hi for lo, hi in self.executable
            ):
                raise ValueError(
                    "entry/call/target outside approved executable whitelist"
                )
        spans = (
            (self.code, self.code + CODE_SIZE),
            (self.mailbox, self.mailbox + SIZE),
        )
        if self.target_stack is not None:
            if (
                not isinstance(self.target_stack, (tuple, list))
                or len(self.target_stack) != 2
            ):
                raise ValueError("target_stack requires an explicit (base, size)")
            base, size = self.target_stack
            if (
                type(base) is not int
                or type(size) is not int
                or physical(base) != base
                or base % 16
                or size % 16
                or not 0x2000 <= size <= 0x10000
            ):
                raise ValueError(
                    "target_stack requires physical 16-aligned RAM and size 0x2000..0x10000"
                )
            check_range(base, size, 16)
            object.__setattr__(self, "target_stack", (base, size))
            if any(base < hi and lo < base + size for lo, hi in spans):
                raise ValueError("target_stack overlaps code/mailbox")
            spans += ((base, base + size),)
        if self.previous_dispatch is not None:
            old = physical(self.previous_dispatch)
            if old != self.previous_dispatch or any(lo <= old < hi for lo, hi in spans):
                raise ValueError(
                    "previous dispatcher must remain outside replacement storage"
                )
        for lo, hi in spans:
            check_range(lo, hi - lo, 16)
            if any(lo < end and start < hi for start, end in self.executable):
                raise ValueError("helper allocation overlaps stock executable extent")
        if spans[0][0] < spans[1][1] and spans[1][0] < spans[0][1]:
            raise ValueError("code/mailbox overlap")
        check_range(self.gamecore + CALL_OFFSET, 8, 4)
        check_range(self.original_usb, len(self.usb_entry) * 4, 4)
        for address in guards(self):
            if not any(
                lo <= address and address + 4 <= hi for lo, hi in self.executable
            ):
                raise ValueError("guard outside approved executable whitelist")


def guards(config):
    """Full-word guards; installer must supply an independently trusted baseline."""
    result = {
        config.gamecore + 0xC668: 0x27BDFFF0,
        config.gamecore + 0xC66C: 0xFFBF0000,
        config.gamecore + 0xC674: 0,
        config.gamecore + CALL_OFFSET: 0x0C000000
        | ((config.previous_dispatch or config.original_usb) >> 2),
        config.gamecore + CALL_OFFSET + 4: config.delay_word,
        config.gamecore + 0xC684: 0,
        config.gamecore + 0xC688: 0x1000FFFB,
        config.gamecore + 0xC68C: 0,
    }
    for i, word in enumerate(config.usb_entry):
        address = config.original_usb + 4 * i
        if address in result and result[address] != word:
            raise ValueError("contradictory entry/call guards")
        result[address] = word
    return result


def render(config, observed):
    for address, word in guards(config).items():
        if type(observed.get(address)) is not int or observed[address] != word:
            raise ValueError(f"original USB entry/call guard failed at {address:#x}")
    lines = [
        ".set noreorder",
        ".set noat",
        '.section .text,"ax",@progbits',
        ".balign 16",
        ".extern original_USB",
        ".globl command_dispatch",
        "command_dispatch:",
        # Save original SP before any arithmetic: retain its full 128 bits.
        "sq $sp, -32($sp)",
        f"addiu $sp, $sp, -{FRAME}",
    ]

    def emit(*items):
        lines.extend(items)

    def branch(op):
        emit(op, "nop")

    def load(reg, value):
        emit(
            f"lui ${reg}, 0x{value >> 16:x}", f"ori ${reg}, ${reg}, 0x{value & 65535:x}"
        )

    # The bottom 64 bytes are outgoing EABI home space, not stack arguments.
    for i, reg in enumerate(GPRS):
        if reg not in ("zero", "sp"):
            emit(f"sq ${reg}, {64 + i * 16}($sp)")
    for i in range(32):
        emit(f"swc1 $f{i}, {576 + i * 4}($sp)")
    for i, op in enumerate(("mfhi", "mflo", "mfhi1", "mflo1")):
        emit(f"{op} $t0", f"sd $t0, {704 + i * 8}($sp)")
    emit("mfsa $t0", "sw $t0, 736($sp)", "cfc1 $t0, $31", "sw $t0, 740($sp)")
    # External PINE writes must not be hidden behind the EE data cache.
    load("t4", config.mailbox | 0xA0000000)
    emit("lw $t5, 8($t4)")
    branch("bne $t5, $zero, restore")
    emit("lw $t5, 84($t4)")
    branch("bne $t5, $zero, restore")
    emit("lw $t5, 0($t4)", "sync", "lw $t6, 12($t4)")
    branch(f"beq $t5, $t6, {'maybe_frame' if config.frame_callback else 'restore'}")
    # Reject zero, stale, skipped or wrapped sequences without running anything.
    branch("beq $t5, $zero, sequence_fault")
    emit("addiu $t7, $t6, 1")
    branch("bne $t5, $t7, sequence_fault")
    emit(
        "addiu $t7, $zero, 1",
        "sw $t7, 8($t4)",
        "sw $t5, 12($t4)",
        "sw $t5, 752($sp)",
        "sync",
        "sw $zero, 72($t4)",
        "sw $zero, 76($t4)",
        "sw $zero, 80($t4)",
        "lw $t6, 20($t4)",
    )
    branch("bne $t6, $t7, bad_operation")
    emit("lw $t6, 16($t4)", f"sltiu $t7, $t6, {len(config.targets)}")
    branch("beq $t7, $zero, bad_target")
    emit(
        "lui $t8, %hi(command_targets)",
        "addiu $t8, $t8, %lo(command_targets)",
        "sll $t6, $t6, 3",
        "addu $t8, $t8, $t6",
        "lw $t9, 0($t8)",
        "andi $t6, $t9, 3",
    )
    branch("bne $t6, $zero, bad_target")
    # Runtime whitelist check also fails closed on corrupted table addresses.
    for i, (lo, hi) in enumerate(config.executable):
        load("t6", lo)
        emit("sltu $t7, $t9, $t6")
        branch(f"bne $t7, $zero, range_next_{i}")
        load("t6", hi)
        emit("sltu $t7, $t9, $t6")
        branch("bne $t7, $zero, allowed")
        emit(f"range_next_{i}:")
    branch("b bad_target")
    emit("allowed:", "lw $gp, 4($t8)")
    for i, reg in enumerate(("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3")):
        emit(f"lw ${reg}, {24 + i * 4}($t4)")
    for i in range(3):
        emit(f"lwc1 $f{12 + i}, {56 + i * 4}($t4)")
    if config.target_stack is not None:
        base, size = config.target_stack
        # Arguments are loaded; t8 is now scratch. Keep the return bridge above
        # the 64-byte outgoing EABI home area, not in any callee-clobbered GPR.
        emit("daddu $t8, $sp, $zero")
        load("sp", base + size - 80)
        emit("sd $t8, 64($sp)")
    branch("jalr $ra, $t9")
    if config.target_stack is not None:
        emit("ld $t8, 64($sp)", "daddu $sp, $t8, $zero")
    # A nonlocal exit never reaches here: BUSY remains set and no reply commits.
    emit("sw $v0, 756($sp)", "sw $v1, 760($sp)", "swc1 $f0, 764($sp)")
    load("t4", config.mailbox | 0xA0000000)
    for i in range(3):
        emit(f"lw $t6, {756 + i * 4}($sp)", f"sw $t6, {72 + i * 4}($t4)")
    emit("addu $t6, $zero, $zero")
    branch("b commit")
    emit("bad_operation:", "addiu $t6, $zero, 1")
    branch("b commit")
    emit("bad_target:", "addiu $t6, $zero, 2", "commit:")
    if config.frame_callback is None:
        emit(
            "sw $t6, 68($t4)",
            "lw $t5, 752($sp)",
            "sw $zero, 8($t4)",
            "sync",
            "sw $t5, 4($t4)",
        )
        branch("b restore")
    else:
        # Keep command BUSY and defer its reply sequence until the frame work
        # returns. These locals live on the dispatch stack, not the call stack.
        emit("sw $t6, 768($sp)", "addiu $t7, $zero, 1", "sw $t7, 772($sp)")
        branch("b frame_call")
        emit("maybe_frame:", "lw $t5, 8($t4)")
        branch("bne $t5, $zero, restore")
        emit("lw $t5, 84($t4)")
        branch("bne $t5, $zero, restore")
        emit("sw $zero, 772($sp)", "addiu $t7, $zero, 1", "sw $t7, 8($t4)")
        emit("frame_call:", "sync")
        load("t9", config.frame_callback.address)
        load("gp", config.frame_callback.gp)
        base, size = config.target_stack
        emit("daddu $t8, $sp, $zero")
        load("sp", base + size - 80)
        emit("sd $t8, 64($sp)")
        branch("jalr $ra, $t9")
        emit("ld $t8, 64($sp)", "daddu $sp, $t8, $zero")
        load("t4", config.mailbox | 0xA0000000)
        emit("lw $t7, 772($sp)")
        branch("beq $t7, $zero, frame_done")
        emit(
            "lw $t6, 768($sp)",
            "sw $t6, 68($t4)",
            "lw $t5, 752($sp)",
            "sw $zero, 8($t4)",
            "sync",
            "sw $t5, 4($t4)",
        )
        branch("b restore")
        emit("frame_done:", "sw $zero, 8($t4)", "sync")
        branch("b restore")
    emit(
        "sequence_fault:", "addiu $t6, $zero, 3", "sync", "sw $t6, 84($t4)", "restore:"
    )
    for i, op in enumerate(("mthi", "mtlo", "mthi1", "mtlo1")):
        emit(f"ld $t0, {704 + i * 8}($sp)", f"{op} $t0")
    emit("lw $t0, 736($sp)", "mtsa $t0")
    for i in range(32):
        emit(f"lwc1 $f{i}, {576 + i * 4}($sp)")
    emit("lw $t0, 740($sp)", "ctc1 $t0, $31")
    for i, reg in enumerate(GPRS):
        if reg not in ("zero", "sp"):
            emit(f"lq ${reg}, {64 + i * 16}($sp)")
    emit(f"lq $sp, {FRAME - 32}($sp)")
    # Tail call with untouched incoming arguments, RA, GP and full register state.
    # The original callback's return values/side effects flow directly to caller.
    branch("j original_USB")
    emit(".balign 16", ".globl command_targets", "command_targets:")
    for target in config.targets:
        emit(f".word 0x{target.address:08x}, 0x{target.gp:08x}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    object_bytes: bytes
    linked: object
    patches: tuple
    initial_mailbox: bytes = bytes(SIZE)


def build(config, observed, *, assembler, objcopy=None):
    assembly = render(config, observed)
    if objcopy is None:
        if not str(assembler).endswith("-as"):
            raise ValueError("supply matching EE objcopy")
        objcopy = str(assembler)[:-3] + "-objcopy"
    with tempfile.TemporaryDirectory(prefix="coop-commands-") as folder:
        source, output = Path(folder) / "commands.s", Path(folder) / "commands.o"
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
        blob = output.read_bytes()
        flags = struct.unpack_from("<I", blob, 36)[0]
        if flags & 0xF000 != 0x4000 or flags & 0xFF0000 != 0x920000:
            raise ValueError("requires R5900 EABI64 object (EE 64-bit GPR ABI)")
        linked = link_object(
            blob,
            {
                ".text": config.code,
                ".data": config.code + CODE_SIZE - 32,
                ".bss": config.code + CODE_SIZE - 16,
            },
            {"original_USB": config.original_usb},
        )
    if any(
        p.address < config.code or p.address + len(p.data) > config.code + CODE_SIZE
        for p in linked.payloads
    ):
        raise ValueError("dispatcher exceeds code reservation")
    target = linked.exports["command_dispatch"]
    site = config.gamecore + CALL_OFFSET
    if (site + 4) >> 28 != target >> 28:
        raise ValueError("JAL crosses instruction region")
    return Build(
        assembly,
        blob,
        linked,
        (WordPatch(site, guards(config)[site], 0x0C000000 | (target >> 2)),),
    )
