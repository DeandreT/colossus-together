"""Offline, attested NTSC-U EE streaming adapters; no hooks or target writes.

G is the DISASSEMBLY image base: actual .text = G+0x38. render() produces
assembly text only; build() requires original XFF provenance and a complete
read-only instruction/table observation before returning linked payloads.

stream_policy(x,z,layer,roundedX,roundedZ,containingX,containingZ) uses seven
EABI register arguments. It enters G+1F028, NOT G+1EF58 (which checks native
load states). The pinned suffix has no SP, GP or callee-saved dependencies:
its only incoming GPRs are t5,t6,t3,a2,a3,t0,t1,t2,ra. Its computed jump table
is separately attested. The wrapper preserves full 128-bit s0-s8, GP, RA, SP;
native caller-saved GPR/FPR/HI/LO may change. F20-F31 are untouched by the
pinned suffix/batcher and remain the native callee's responsibility.

stream_batch(BatchArgs*) accepts ten u32 words: coords,count,minX,minZ,width,
height,roundedX,roundedZ,containingX,containingZ. coords use NATIVE 16-byte
stride (not planner su_coord's 8). Nonempty, in-map tiles <=16x16 only. The
wrapper checks every coordinate before any native call, reserves 64 outgoing
home bytes, puts the last arguments at call-SP+0/+8, and returns 1 after the
void native batcher returns, 0 for invalid input. Original callers' homes are
not changed. Native batching retains ownership of its own request work.

Runtime pointers must be readable, immutable for the call and disjoint from
the caller's active stack. Bounds checks are not an allocation/provenance
oracle. Startup bindings and observations must be refreshed/revalidated by
the future installer; generating these bytes does not install any guard.
The caller must supply a 16-byte-aligned EABI stack with room for the 256-byte
adapter frame plus native nested frames. Empty tiles are omitted by the planner
and rejected here. Rounded centers may equal W/H at an edge; containing cells
and candidate cells must be strictly inside. HI/LO and FP condition flags are
caller-saved; the policy uses native FP comparisons, not a host approximation.

Radius evidence: D_17A314/318 are signed integer chip counts. G+1F198 loads
314 with lwc1, then G+1F19C cvt.s.w interprets its bits as an INTEGER; G+1F2D4
and 1F2DC use lw and integer addition for 314+318. G+22014..22068 and
2207C..220A8 copy integer targets using lw/sw/slt. Only D_17A3B0 and
B_18860C are float fog values (G+21FEC..21FF8). No fractional-radius adapter
or truncation is authorized. World-position conversion still needs finite
float validation in a separate adapter. This module has no float inputs.

State 5 is not an interest-return cancellation token. The missing-file branch
G+235C4..236A8 builds a completion parameter with +8=5 (23628/2362C), sets the
slot to 4, and schedules G+1F8E8; its completion writes that 5 into the slot at
G+1F9E0..1FA08. G+248F4..24908 suppresses deletion only while initially
dispatching op 3. Once G+24BA8 has been scheduled, it uses the captured layout
pointer and never reads a cell state. Neither the selector nor the batcher
writes 5 to cancel an unload. A later interest must be handled before dispatch
or through a separate late revalidation seam, not by forging native state 5.
"""

import hashlib
import os
import struct
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from runtime.elf import LinkedObject, link_object
from runtime.xff import parse

EE_SIZE = 0x2000000
TEXT_BIAS = 0x38
POLICY = 0x1F028
BATCH = 0x1FF70
CODE_SIZE = 0x1000
FRAME = 256
SAVED = tuple((name, 64 + i * 16) for i, name in enumerate(
    ("s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "fp", "gp", "ra")))
SAVED_SP = 240
# Checksum, not copyrighted instruction contents. Exact original revision only.
TEXT_SHA256 = "40f5e0b9e20ff3a866890c290a7d3c15b4be71394b57b55b054a4d1fcbb4908e"
XFF_SHA256 = "fba772ac8c793281af15be204243098b999e91b229ad3074a39a9773a56676f9"
GUARD_RANGES = (
    (0x1EF58, 0x1F560), (0x1FF70, 0x20850),
    (0x20C98, 0x20CC8), (0x20D94, 0x20DF8), (0x20FB8, 0x21020),
    (0x21FC0, 0x220C0),
)
TABLE_TARGETS = (0x1F378, 0x1F078, 0x1F0F0, 0x1F0F0, 0x1F378, 0x1F378)


def _uint(value):
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def _region(address, size, alignment=4):
    return (_uint(address) and type(size) is int and size > 0 and
            address % alignment == 0 and address + size <= EE_SIZE)


@dataclass(frozen=True)
class Config:
    g: int
    gp: int
    code: int
    width: int
    height: int
    trusted_code: tuple[tuple[int, int], ...]

    def __post_init__(self):
        if not _region(self.g, 0x220C0) or not self.gp or not _region(self.gp, 4):
            raise ValueError("invalid disassembly G or explicit native GP")
        if not _region(self.code, CODE_SIZE, 16):
            raise ValueError("invalid reserved output code extent")
        if (type(self.width) is not int or type(self.height) is not int or
                not 0 < self.width <= 4096 or not 0 < self.height <= 4096 // self.width):
            raise ValueError("map dimensions exceed 4096 cells")
        for base, size in self.trusted_code:
            if not _region(base, size) or size % 4:
                raise ValueError("invalid executable whitelist")
            if self.code < base + size and base < self.code + CODE_SIZE:
                raise ValueError("output overlaps native executable code")
        for lo, hi in ((POLICY, 0x1F560), (BATCH, 0x20850)):
            if not any(b <= self.g + lo and self.g + hi <= b + n
                       for b, n in self.trusted_code):
                raise ValueError("native callee extent is not whitelisted")


@dataclass(frozen=True)
class Evidence:
    original_xff: bytes
    provenance: str
    # Actual, independently verified section addresses, not disassembly offsets.
    section_bases: Mapping[str, int]
    imports: Mapping[str, int]
    observed_words: Mapping[int, int]


def expected_guards(c: Config, evidence: Evidence) -> dict[int, int]:
    """Reconstruct exact loaded guards from the pinned original and bindings.

    Caller supplies provenance and independently verified section/import bases.
    Both the entire XFF (including metadata) and its text are revision-pinned.
    This never reads a process. Returned words include the native jump table.
    """
    if not isinstance(evidence.provenance, str) or not evidence.provenance.strip():
        raise ValueError("original source provenance required")
    if (not isinstance(evidence.original_xff, bytes) or
            hashlib.sha256(evidence.original_xff).hexdigest() != XFF_SHA256):
        raise ValueError("unsupported original GAMECORE XFF/metadata revision")
    module = parse(evidence.original_xff)
    ti = module.index_of(".text")
    raw = module.sections[ti].data
    if raw is None or hashlib.sha256(raw).hexdigest() != TEXT_SHA256:
        raise ValueError("unsupported original GAMECORE text revision")
    bases = dict(evidence.section_bases)
    imports = dict(evidence.imports)
    if bases.get(".text") != c.g + TEXT_BIAS:
        raise ValueError("actual .text must equal disassembly G + 0x38")
    for name, base in bases.items():
        section = module.sections[module.index_of(name)]
        if not _region(base, max(section.size, 4)):
            raise ValueError("invalid verified section extent")
        if c.code < base + section.size and base < c.code + CODE_SIZE:
            raise ValueError("output overlaps a native section")
    guarded = {off - TEXT_BIAS for lo, hi in GUARD_RANGES
               for off in range(lo, hi, 4)}
    expected = {off: struct.unpack_from("<I", raw, off)[0] for off in guarded}

    def target(index):
        symbol = module.symbol(index)
        name, value, section = module.symbol_name(index), symbol[1], symbol[5]
        if section:
            if section >= len(module.sections):
                raise ValueError("unsupported relocation section")
            base = bases.get(module.section_name(section))
            if base is None:
                raise ValueError("missing verified section binding")
            result = base + value
        else:
            result = imports.get(name)
            if not _region(result, 4):
                raise ValueError(f"missing verified import {name}")
        if not _uint(result):
            raise ValueError("relocation target overflow")
        return result

    assigned = {}

    def put(off, word):
        if off not in guarded:
            return
        if not _uint(word) or (off in assigned and assigned[off] != word):
            raise ValueError("inconsistent native relocation")
        assigned[off] = word
        expected[off] = word

    for table in module.reltables:
        if table.target != ti:
            continue
        highs = {}
        for off, info, saved, _extra in table.entries:
            index, kind = info >> 8, info & 255
            if kind == 5:
                highs[index] = (off, saved)
            elif kind == 6:
                high = highs.get(index)
                if off not in guarded and (high is None or high[0] not in guarded):
                    continue
                if high is None:
                    raise ValueError("unpaired guarded native LO16")
                ho, hw = high
                low = (saved & 65535) - (65536 if saved & 32768 else 0)
                value = target(index) + ((hw & 65535) << 16) + low
                if not _uint(value):
                    raise ValueError("native HI/LO overflow")
                put(ho, (hw & 0xFFFF0000) | (((value + 32768) >> 16) & 65535))
                put(off, (saved & 0xFFFF0000) | (value & 65535))
            elif off in guarded:
                if kind == 4:
                    value = target(index) + ((saved & 0x3FFFFFF) << 2)
                    address = c.g + TEXT_BIAS + off
                    if not _region(value, 4) or (value ^ (address + 4)) & 0xF0000000:
                        raise ValueError("native J/JAL relocation region")
                    if not any(b <= value < b + size for b, size in c.trusted_code):
                        raise ValueError("native code dependency is not whitelisted")
                    put(off, (saved & 0xFC000000) | (value >> 2 & 0x3FFFFFF))
                elif kind == 2:
                    put(off, target(index) + saved)
                else:
                    raise ValueError("unsupported guarded relocation")
    result = {c.g + TEXT_BIAS + off: word for off, word in expected.items()}
    state_hi = result[c.g + 0x1F028] & 65535
    state_lo = result[c.g + 0x1F030] & 65535
    state = (state_hi << 16) + state_lo - (65536 if state_lo & 32768 else 0)
    if not _region(state, 0x50):
        raise ValueError("invalid native stream-state binding")
    result[state + 0x48] = c.width
    result[state + 0x4C] = c.height
    hi = result[c.g + 0x1F064] & 65535
    lo = result[c.g + 0x1F06C] & 65535
    table_address = (hi << 16) + lo - (65536 if lo & 32768 else 0)
    if not _region(table_address, 24):
        raise ValueError("invalid policy jump table")
    for i, offset in enumerate(TABLE_TARGETS):
        result[table_address + i * 4] = c.g + offset
    return result


def verify(c: Config, evidence: Evidence):
    guards = expected_guards(c, evidence)
    observed = dict(evidence.observed_words)
    for address, word in guards.items():
        if not _uint(observed.get(address)) or observed[address] != word:
            raise ValueError(f"missing/changed original guard at {address:#x}")


def _load(reg, value):
    return [f"lui ${reg},0x{value >> 16:04x}",
            f"ori ${reg},${reg},0x{value & 65535:04x}"]


def _enter():
    return ["por $t8,$sp,$zero", f"addiu $sp,$sp,-{FRAME}",
            f"sq $t8,{SAVED_SP}($sp)"] + [f"sq ${r},{o}($sp)" for r, o in SAVED]


def _leave(label):
    return [f"{label}:"] + [f"lq ${r},{o}($sp)" for r, o in SAVED] + [
        f"lq $sp,{SAVED_SP}($sp)", "jr $ra", "nop"]


def render(c: Config) -> str:
    """Generate assembly only. build(), unlike render(), requires evidence."""
    lines = [".set noreorder", ".set noat", '.section .text,"ax",@progbits',
             ".balign 16", ".globl stream_policy", "stream_policy:"] + _enter()
    lines += ["sltiu $t7,$a2,2", "beq $t7,$zero,policy_bad", "nop"]
    for reg, bound in (("a0", c.width - 1), ("a1", c.height - 1),
                       ("t1", c.width - 1), ("t2", c.height - 1),
                       ("a3", c.width), ("t0", c.height)):
        lines += [f"sltiu $t7,${reg},{bound + 1}",
                  "beq $t7,$zero,policy_bad", "nop"]
    lines += ["por $t5,$a0,$zero", "por $t6,$a1,$zero"]
    lines += _load("t7", c.width)
    lines += ["multu $a1,$t7", "mfhi $t8", "bne $t8,$zero,policy_bad", "nop",
              "mflo $t3", "addu $t3,$t3,$a0", "sltu $t8,$t3,$a0",
              "bne $t8,$zero,policy_bad", "nop"]
    lines += _load("gp", c.gp) + _load("t9", c.g + POLICY)
    lines += ["jalr $t9", "nop", "b policy_done", "nop", "policy_bad:",
              "or $v0,$zero,$zero"] + _leave("policy_done")
    lines += [".balign 16", ".globl stream_batch", "stream_batch:"] + _enter()
    lines += ["beq $a0,$zero,batch_bad", "nop", "andi $t4,$a0,3",
              "bne $t4,$zero,batch_bad", "nop"]
    lines += _load("t4", EE_SIZE - 40)
    lines += ["sltu $t5,$t4,$a0", "bne $t5,$zero,batch_bad", "nop",
              "por $t8,$a0,$zero", "lw $t4,0($t8)", "lw $t5,4($t8)",
              "beq $t4,$zero,batch_bad", "nop", "andi $t6,$t4,15",
              "bne $t6,$zero,batch_bad", "nop", "beq $t5,$zero,batch_bad", "nop",
              "sltiu $t6,$t5,257", "beq $t6,$zero,batch_bad", "nop",
              "sll $t6,$t5,4", "addu $t7,$t4,$t6", "sltu $t6,$t7,$t4",
              "bne $t6,$zero,batch_bad", "nop"]
    lines += _load("t6", EE_SIZE)
    lines += ["sltu $t6,$t6,$t7", "bne $t6,$zero,batch_bad", "nop",
              "lw $t6,16($t8)", "lw $t7,20($t8)",
              "beq $t6,$zero,batch_bad", "nop", "beq $t7,$zero,batch_bad", "nop",
              "sltiu $t9,$t6,17", "beq $t9,$zero,batch_bad", "nop",
              "sltiu $t9,$t7,17", "beq $t9,$zero,batch_bad", "nop",
              "multu $t6,$t7", "mflo $t9", "sltu $t9,$t9,$t5",
              "bne $t9,$zero,batch_bad", "nop",
              "lw $a2,8($t8)", "lw $a3,12($t8)"]
    for reg, limit in (("a2", c.width), ("a3", c.height)):
        lines += [f"sltiu $t9,${reg},{limit}", "beq $t9,$zero,batch_bad", "nop"]
    lines += ["addu $a0,$a2,$t6", "addu $a1,$a3,$t7"]
    for reg, limit in (("a0", c.width), ("a1", c.height)):
        lines += [f"sltiu $t9,${reg},{limit + 1}",
                  "beq $t9,$zero,batch_bad", "nop"]
    for offset, limit in ((24, c.width + 1), (28, c.height + 1),
                          (32, c.width), (36, c.height)):
        lines += [f"lw $t9,{offset}($t8)", f"sltiu $t9,$t9,{limit}",
                  "beq $t9,$zero,batch_bad", "nop"]
    lines += ["batch_coords:", "lw $t6,0($t4)", "lw $t7,4($t4)",
              "sltu $t9,$t6,$a2", "bne $t9,$zero,batch_bad", "nop",
              "sltu $t9,$t7,$a3", "bne $t9,$zero,batch_bad", "nop",
              "sltu $t9,$t6,$a0", "beq $t9,$zero,batch_bad", "nop",
              "sltu $t9,$t7,$a1", "beq $t9,$zero,batch_bad", "nop",
              "addiu $t5,$t5,-1", "addiu $t4,$t4,16",
              "bne $t5,$zero,batch_coords", "nop"]
    for reg, offset in (("a0", 0), ("a1", 4), ("a2", 8), ("a3", 12),
                        ("t0", 16), ("t1", 20), ("t2", 24), ("t3", 28)):
        lines += [f"lw ${reg},{offset}($t8)"]
    lines += ["lw $t9,32($t8)", "sw $t9,0($sp)",
              "lw $t9,36($t8)", "sw $t9,8($sp)"]
    lines += _load("gp", c.gp) + _load("t9", c.g + BATCH)
    lines += ["jalr $t9", "nop", "addiu $v0,$zero,1", "b batch_done", "nop",
              "batch_bad:", "or $v0,$zero,$zero"] + _leave("batch_done")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: LinkedObject


def _assemble(c, assembly, assembler):
    with tempfile.TemporaryDirectory(prefix="streaming-native-") as directory:
        source, obj = Path(directory) / "native.s", Path(directory) / "native.o"
        source.write_text(assembly)
        subprocess.run([str(assembler), "-march=r5900", "-mabi=eabi", "-o",
                        str(obj), str(source)], check=True, capture_output=True)
        assembler_path = Path(assembler)
        if not assembler_path.name.endswith("as"):
            raise ValueError("assembler name must end in as; set SOTC_EE_AS")
        objcopy = os.environ.get("SOTC_EE_OBJCOPY", str(assembler_path.with_name(
            assembler_path.name[:-2] + "objcopy")))
        subprocess.run([objcopy, "--remove-section=.MIPS.abiflags",
                        "--remove-section=.reginfo", str(obj)],
                       check=True, capture_output=True)
        linked = link_object(obj.read_bytes(), {
            ".text": c.code, ".data": c.code + CODE_SIZE - 32,
            ".bss": c.code + CODE_SIZE - 16,
        })
    if any(p.address < c.code or p.address + len(p.data) > c.code + CODE_SIZE
           for p in linked.payloads):
        raise ValueError("adapters exceed reserved output")
    return linked


def build(c: Config, evidence: Evidence, *, assembler=None) -> Build:
    verify(c, evidence)
    if assembler is None:
        assembler = os.environ.get("SOTC_EE_AS", "mips64r5900el-ps2-elf-as")
    assembly = render(c)
    return Build(assembly, _assemble(c, assembly, assembler))
