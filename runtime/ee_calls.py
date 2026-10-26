"""Authored fixed-target R5900 EABI call veneers; no game code is copied.

Callers must supply an at least 8-byte-aligned physical EE stack and at most
eight register arguments (a0-a3, t0-t3), plus native FPU arguments. Stack-passed
arguments, including a ninth integer argument, are NOT supported: this veneer
does not relocate them. Misaligned callers are unsupported, not trapped.

Each invocation aligns its own stack down to 16 bytes and reserves 112 bytes:
64 bytes of callee-owned outgoing EABI home space, then full 128-bit SP/GP/RA
at offsets 64/80/96. Maximum SP displacement is 120 bytes for an 8-mod-16
caller: a 119-byte displacement limit is incompatible with a 112-byte frame
and 16-byte alignment at that entry alignment. No allocator or global scratch
is used, so a yielding target or nested callback retains its own frame.
Only t8/t9 and native caller-saved state may change; v0/v1/f0 return untouched.
HI/LO, FPU scratch and other registers follow the target's native ABI contract.
"""

import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from runtime.elf import link_object


def _physical(value, alignment=1):
    return type(value) is int and 0 < value < 0x02000000 and value % alignment == 0


def render(label: str, target: int, gp: int) -> str:
    """Return assembly for one validated fixed native call, never a runtime pointer.

    ``target`` is a nonzero, 4-byte-aligned physical EE RAM code address; ``gp``
    is a nonzero physical EE RAM address (no extra GP alignment is assumed).
    The caller owns enough writable stack below SP, including alignment padding.
    """
    if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", label):
        raise ValueError("function label must be a plain assembler identifier")
    if not _physical(target, 4):
        raise ValueError("target must be a 4-byte-aligned physical EE code address")
    if not _physical(gp):
        raise ValueError("GP must be a physical EE address")
    return f""".set noreorder
.set noat
.text
.balign 16
.globl {label}
.type {label}, @function
{label}:
por $t8, $sp, $zero
addiu $sp, $sp, -112
addiu $t9, $zero, -16
and $sp, $sp, $t9
sq $t8, 64($sp)
sq $gp, 80($sp)
sq $ra, 96($sp)
lui $gp, {gp >> 16}
ori $gp, $gp, {gp & 0xFFFF}
lui $t9, {target >> 16}
ori $t9, $t9, {target & 0xFFFF}
jalr $ra, $t9
nop
lq $ra, 96($sp)
lq $gp, 80($sp)
lq $sp, 64($sp)
jr $ra
nop
.size {label}, .-{label}
"""


def build(label: str, target: int, gp: int, address: int, *, assembler=None, objcopy=None):
    """Assemble and link one veneer at ``address``; never install or execute it.

    Returns runtime.elf.LinkedObject. The optional EE assembler is selected by
    explicit argument, SOTC_EE_AS, then PATH; no private inputs are discovered.
    """
    assembly = render(label, target, gp)
    if not _physical(address, 16) or address + 80 > 0x02000000:
        raise ValueError("veneer placement must be aligned physical EE RAM")
    assembler = assembler or os.environ.get("SOTC_EE_AS") or "mips64r5900el-ps2-elf-as"
    objcopy = objcopy or os.environ.get("SOTC_EE_OBJCOPY") or (
        str(assembler)[:-2] + "objcopy" if str(assembler).endswith("as")
        else "mips64r5900el-ps2-elf-objcopy"
    )
    with tempfile.TemporaryDirectory(prefix="ee-call-") as folder:
        source, output = Path(folder) / "call.s", Path(folder) / "call.o"
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
        flags = struct.unpack_from("<I", output.read_bytes(), 36)[0]
        if flags & 0xF000 != 0x4000 or flags & 0xFF0000 != 0x920000:
            raise ValueError("requires R5900 EABI64 object")
        subprocess.run(
            [str(objcopy), "--remove-section=.MIPS.abiflags", "--remove-section=.reginfo", str(output)],
            check=True,
            capture_output=True,
        )
        return link_object(
            output.read_bytes(),
            {
                ".text": address,
                ".data": address + 80,
                ".bss": address + 80,
            },
        )
