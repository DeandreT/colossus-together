"""Offline streaming hook payload/patch generator; never installs or executes.

G is the listing/image base, actual .text is G+0x38. All original targets are
explicit verified bindings. Callbacks have one explicit GP, must return normally
without recursive streaming, and must leave FPACC/VU state alone (not observable
by this glue). Boolean callbacks return exactly 0/1; they have no error sentinel.
predicate receives (ctx,x,z,layer,roundedX,roundedZ,containingX,containingZ)
in all eight EABI argument registers; no native fallback argument is discarded.
The future provider owns fault reporting/admission in ctx. submit(ctx,args) owns
ALL submission, including native batching; this hook never duplicates it or
silently falls back. begin/refresh_keep/fallback return values are ignored.
The provider must account for or explicitly report failed submissions in ctx;
a void return is not evidence that it queued anything. Installer/provider fault
handling and target-body attestation are required before use, not supplied here.

Callbacks may clobber GPRs, HI/LO, SA, FPRs and FCSR. Glue restores full 128-bit
GPR/HI/LO state and 32-bit FPR/FCSR/SA, except predicate v0 is its result. begin
restores the actual original callee's post-state, not the pre-call state. fallback
restores pre-state before tail-calling maintenance once. Native operations retain
their ordinary side effects. No wrapper writes a native cell-state word.

Stack: FULL_FRAME=848, begin's original-call home frame=128. Maximum local glue
depth is 976 bytes. A submit -> stream_batch -> native batcher -> predicate path
has two 848-byte hook frames, 256-byte adapter, 208-byte batch frame and <=1024
grid, plus 160-byte stream loop/176-byte selector = 3520 known bytes. Provider,
allocator and other native nested frames are ADDITIONAL, not a proved 8KiB bound.
Full snapshots are coroutine-stack resident, not global scratch. Inputs/ctx must
not alias these frames. The entry refresh frame is gone before the original
96-byte unloader prologue executes.
"""

import hashlib
import os
import struct
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from runtime.elf import LinkedObject, link_object
from runtime.patches import WordPatch
from runtime.xff import parse

from .native import XFF_SHA256

CODE_SIZE = 0x6000
FULL_FRAME, PRE_FRAME = 848, 128
GPRS, FPRS, HI, LO, SA, FCSR = 64, 576, 704, 720, 736, 740
BATCH_ARGS, RESULT, SAVED_SP = 752, 800, 832
CALLS = {"begin": 0x221AC, "submit_a": 0x20CB8, "submit_b": 0x20DB8,
         "submit_c": 0x20FE4, "predicate": 0x200F0, "fallback": 0x22764}
EVICTIONS = ((0x2136C, 0x21384), (0x214CC, 0x214E4), (0x216EC, 0x21704))
ORIGINAL_OFFSETS = {"chip": 0x1EA58, "batch": 0x1FF70, "predicate": 0x1EF58,
                    "maintenance": 0x21FC0, "unlink": 0x1EC38, "unload": 0x1FA68}
CALLBACKS = frozenset(("begin", "submit", "predicate", "refresh_keep", "keep", "fallback"))


def _address(a, size=4, alignment=4):
    return (type(a) is int and type(size) is int and size > 0 and
            0x80000 <= a and a % alignment == 0 and a + size <= 0x2000000)


def _jump(a, link=False):
    return (0x0C000000 if link else 0x08000000) | (a >> 2)


@dataclass(frozen=True)
class Config:
    g: int
    code: int
    context: int
    context_size: int
    callback_gp: int
    callbacks: Mapping[str, int]
    originals: Mapping[str, int]  # ORIGINAL_OFFSETS keys plus ios_free
    trusted_code: tuple[tuple[int, int], ...]
    code_size: int = CODE_SIZE

    def __post_init__(self):
        object.__setattr__(self, "callbacks", MappingProxyType(dict(self.callbacks)))
        object.__setattr__(self, "originals", MappingProxyType(dict(self.originals)))
        object.__setattr__(self, "trusted_code", tuple(tuple(span) for span in self.trusted_code))
        if (type(self.code_size) is not int or self.code_size < 32 or
                self.code_size > 0x10000 or self.code_size % 16 or
                not _address(self.g, 0x22800) or not _address(self.code, self.code_size, 16)):
            raise ValueError("invalid listing base or owned code extent")
        if not _address(self.context, self.context_size, 16) or not _address(self.callback_gp):
            raise ValueError("invalid context extent or callback GP")
        if set(self.callbacks) != CALLBACKS or set(self.originals) != set(ORIGINAL_OFFSETS) | {"ios_free"}:
            raise ValueError("explicit complete callback/original bindings required")
        spans = ((self.code, self.code_size), (self.context, self.context_size))
        if spans[0][0] < spans[1][0] + spans[1][1] and spans[1][0] < spans[0][0] + spans[0][1]:
            raise ValueError("owned code/context overlap")
        for base, size in self.trusted_code:
            if not _address(base, size) or size % 4:
                raise ValueError("invalid executable whitelist")
            if any(a < base + size and base < a + length for a, length in spans):
                raise ValueError("owned code/context overlaps native/provider code")
        for name, target in tuple(self.callbacks.items()) + tuple(self.originals.items()):
            if not _address(target) or not any(b <= target < b + size for b, size in self.trusted_code):
                raise ValueError(f"untrusted/misaligned target {name}")
        for name, off in ORIGINAL_OFFSETS.items():
            if self.originals[name] != self.g + off:
                raise ValueError(f"wrong listing-base original {name}")
        for a in guard_expectations(self):
            if not _address(a) or any(b <= a < b + size for b, size in spans):
                raise ValueError("guard overlaps owned memory or exceeds RAM")


@dataclass(frozen=True)
class Evidence:
    original_xff: bytes
    provenance: str
    observed_words: Mapping[int, int]


def _specs():
    # int = relocation-free original word; str = explicit JAL binding.
    specs = {
        0x221A4: 0x03A0282D, 0x221A8: 0x02C0202D, 0x221AC: "chip",
        0x221B0: 0x27A60004, 0x221B4: 0xC6C10000,
        0x20CA8: 0x0040302D, 0x20CAC: 0x25080001, 0x20CB0: 0x25290001,
        0x20CB4: 0xAFB60000, 0x20CB8: "batch", 0x20CBC: 0xAFB50008,
        0x20CC0: "ios_free", 0x20CC4: 0x0280202D,
        0x20DB0: 0x03C0402D, 0x20DB4: 0xAFB60000, 0x20DB8: "batch",
        0x20DBC: 0xAFB50008, 0x20DC0: "ios_free", 0x20DC4: 0x0280202D,
        0x20DC8: 0xDFB00060, 0x20DCC: 0xDFB10068, 0x20DD0: 0xDFB20070,
        0x20DD4: 0xDFB30078, 0x20DD8: 0xDFB40080, 0x20DDC: 0xDFB50088,
        0x20DE0: 0xDFB60090, 0x20DE4: 0xDFB70098, 0x20DE8: 0xDFBE00A0,
        0x20DEC: 0xDFBF00A8, 0x20DF0: 0x03E00008, 0x20DF4: 0x27BD00B0,
        0x20FD0: 0x0220382D, 0x20FD4: 0x02A0202D, 0x20FD8: 0x25080001,
        0x20FDC: 0x25290001, 0x20FE0: 0xAFBE0000, 0x20FE4: "batch",
        0x20FE8: 0xAFB70008, 0x20FEC: 0xDFB00020, 0x20FF0: 0x02A0202D,
        0x20FF4: 0xDFB10028, 0x20FF8: 0xDFB20030, 0x20FFC: 0xDFB30038,
        0x21000: 0xDFB40040, 0x21004: 0xDFB50048, 0x21008: 0xDFB60050,
        0x2100C: 0xDFB70058, 0x21010: 0xDFBE0060, 0x21014: 0xDFBF0068,
        0x21018: "j_ios_free", 0x2101C: 0x27BD0070,
        0x200D0: 0x01C0502D, 0x200D4: 0x0200302D, 0x200D8: 0x00952021,
        0x200DC: 0x02E0402D, 0x200E0: 0x00B62821, 0x200E4: 0x7FCB0020,
        0x200E8: 0x7FCC0030, 0x200EC: 0x7FCD0040, 0x200F0: "predicate",
        0x200F4: 0x7FCE0050, 0x200F8: 0x7BCB0020, 0x200FC: 0x7BCC0030,
        0x20100: 0x7BCD0040, 0x20104: 0x1040FFE4, 0x20108: 0x7BCE0050,
        0x21020: 0x27BDFFA0, 0x21024: 0xFFB20010, 0x21028: 0x00C0902D,
        0x2102C: 0xFFB10008, 0x21030: 0x00E0882D, 0x21034: 0xFFB70038,
        0x21038: 0x00A0B82D, 0x2103C: 0xFFBE0040, 0x21040: 0x0080F02D,
        0x22760: 0x0280A82D, 0x22764: "maintenance", 0x22768: 0,
        0x2276C: 0x8E620008, 0x22770: 0x1440FE7F, 0x22774: 0,
    }
    for (site, _next), branch in zip(EVICTIONS, (0x5600FF79, 0x5600FFB1, 0x5600FF85)):
        specs.update({site: "unlink", site + 4: 0x0200202D,
                      site + 8: 0x8E040008, site + 12: 0x8E050000,
                      site + 16: "unload", site + 20: 0x8E060004,
                      site + 24: 0x8E100018, site + 28: branch,
                      site + 32: 0x8E040000})
    # State-6 paths are observed but never patched.
    for site in (0x21248, 0x21438, 0x215E0):
        specs.update({site: "unlink", site + 4: 0x0200202D,
                      site + 8: 0x8E040008, site + 12: 0x8E050000,
                      site + 16: "unload", site + 20: 0x8E060004})
    return specs


def guard_expectations(c):
    return {c.g + off: (_jump(c.originals[word.removeprefix("j_")], not word.startswith("j_"))
                        if isinstance(word, str) else word)
            for off, word in _specs().items()}


def verify(c, evidence):
    if not isinstance(evidence.provenance, str) or not evidence.provenance.strip():
        raise ValueError("original source provenance required")
    if not isinstance(evidence.original_xff, bytes) or hashlib.sha256(evidence.original_xff).hexdigest() != XFF_SHA256:
        raise ValueError("unsupported original XFF/metadata")
    module = parse(evidence.original_xff)
    raw = module.sections[module.index_of(".text")].data
    expected = guard_expectations(c)
    for off, spec in _specs().items():
        if isinstance(spec, str):
            name = spec.removeprefix("j_")
            raw_expected = _jump(ORIGINAL_OFFSETS[name] - 0x38, not spec.startswith("j_")) if name != "ios_free" else (0x08000000 if spec.startswith("j_") else 0x0C000000)
        else:
            raw_expected = spec
        if struct.unpack_from("<I", raw, off - 0x38)[0] != raw_expected:
            raise ValueError(f"original contract mismatch at G+{off:x}")
        if type(evidence.observed_words.get(c.g + off)) is not int or evidence.observed_words[c.g + off] != expected[c.g + off]:
            raise ValueError(f"missing/changed observed guard at G+{off:x}")


def _load(reg, value):
    return [f"lui ${reg},0x{value >> 16:04x}", f"ori ${reg},${reg},0x{value & 65535:04x}"]


def _capture():
    # Use captured AT, never interrupt-volatile K0/K1, for multi-instruction copies.
    lines = ["sq $sp,-16($sp)", f"addiu $sp,$sp,-{FULL_FRAME}"]
    lines += [f"sq ${i},{GPRS + i * 16}($sp)" for i in range(1, 32) if i != 29]
    lines += [f"swc1 $f{i},{FPRS + i * 4}($sp)" for i in range(32)]
    return lines + ["pmfhi $at", f"sq $at,{HI}($sp)", "pmflo $at", f"sq $at,{LO}($sp)",
                    "mfsa $at", f"sw $at,{SA}($sp)", "cfc1 $at,$31", f"sw $at,{FCSR}($sp)"]


def _restore(result=False):
    lines = [f"lq $at,{HI}($sp)", "pmthi $at", f"lq $at,{LO}($sp)", "pmtlo $at",
             f"lw $at,{SA}($sp)", "mtsa $at", f"lw $at,{FCSR}($sp)", "ctc1 $at,$31"]
    lines += [f"lwc1 $f{i},{FPRS + i * 4}($sp)" for i in range(32)]
    lines += [f"lq ${i},{GPRS + i * 16}($sp)" for i in range(1, 32) if i != 29 and not (result and i == 2)]
    if result:
        lines += [f"lq $v0,{RESULT}($sp)"]
    return lines + [f"lq $sp,{SAVED_SP}($sp)"]


def _callback(c, name):
    return _load("gp", c.callback_gp) + [f"jal cb_{name}", "nop"]


def render(c):
    """Assembly text only; build requires source and observed guards."""
    lines = [".set noreorder", ".set noat", '.section .text,"ax",@progbits', ".balign 16"]
    for name, address in c.callbacks.items():
        lines += [f".equ cb_{name},0x{address:x}"]
    for name, address in c.originals.items():
        lines += [f".equ orig_{name},0x{address:x}"]
    lines += [".globl hook_begin", "hook_begin:", "sq $ra,-64($sp)",
              "sq $sp,-48($sp)", "sq $at,-32($sp)", f"addiu $sp,$sp,-{PRE_FRAME}"]
    # Preserve incoming AT around pre-call copies, before the full post-capture.
    for off in range(0, 64, 16):
        lines += [f"lq $at,{PRE_FRAME + off}($sp)", f"sq $at,{off}($sp)"]
    lines += ["lq $at,96($sp)", "jal orig_chip", "nop"] + _capture()
    lines += _load("a0", c.context) + _callback(c, "begin") + _restore()
    lines += ["lq $ra,64($sp)", "lq $sp,80($sp)", "jr $ra", "nop", ".balign 16",
              ".globl hook_submit", "hook_submit:"] + _capture()
    for i in range(8):
        lines += [f"lw $at,{GPRS + (4 + i) * 16}($sp)", f"sw $at,{BATCH_ARGS + i * 4}($sp)"]
    # Both AT and T9 have already been captured at full width.
    lines += [f"lq $at,{SAVED_SP}($sp)", "lw $t9,0($at)", f"sw $t9,{BATCH_ARGS + 32}($sp)",
              "lw $t9,8($at)", f"sw $t9,{BATCH_ARGS + 36}($sp)"]
    lines += _load("a0", c.context) + [f"addiu $a1,$sp,{BATCH_ARGS}"]
    lines += _callback(c, "submit") + _restore() + ["jr $ra", "nop", ".balign 16",
                                                    ".globl hook_predicate", "hook_predicate:"] + _capture()
    # All seven original getEnable arguments survive outside provider scope.
    for dest, source in (("a1", 4), ("a2", 5), ("a3", 6), ("t0", 7),
                         ("t1", 8), ("t2", 9), ("t3", 10)):
        lines += [f"lw ${dest},{GPRS + source * 16}($sp)"]
    lines += _load("a0", c.context) + _callback(c, "predicate")
    lines += [f"sq $v0,{RESULT}($sp)"] + _restore(True) + ["jr $ra", "nop", ".balign 16",
                                                        ".globl hook_refresh", "hook_refresh:"] + _capture()
    lines += _load("a0", c.context) + _callback(c, "refresh_keep") + _restore()
    lines += ["addiu $sp,$sp,-96", "sd $s2,16($sp)", f"j 0x{c.g + 0x21028:x}", "nop"]
    for i, (site, nxt) in enumerate(EVICTIONS):
        lines += [".balign 16", f".globl hook_keep_{i}", f"hook_keep_{i}:"] + _capture()
        lines += _load("a0", c.context) + [f"lw $a1,{GPRS + 16 * 16}($sp)"]
        lines += _callback(c, "keep") + [f"beq $v0,$zero,keep_false_{i}", "nop"]
        lines += _restore() + [f"j 0x{c.g + nxt:x}", "nop", f"keep_false_{i}:"] + _restore()
        # Recreate the original JAL's link, then tail-transfer to unlink with
        # its original delay. Its real post-state proceeds at the original PC.
        lines += _load("ra", c.g + site + 8) + ["j orig_unlink", "daddu $a0,$s0,$zero"]
    lines += [".balign 16", ".globl hook_fallback", "hook_fallback:"] + _capture()
    lines += _load("a0", c.context) + _callback(c, "fallback") + _restore()
    lines += ["j orig_maintenance", "nop"]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Build:
    assembly: str
    linked: LinkedObject
    patches: tuple[WordPatch, ...]


def _assemble(c, assembly, assembler):
    with tempfile.TemporaryDirectory(prefix="streaming-hooks-") as directory:
        src, obj = Path(directory) / "hooks.s", Path(directory) / "hooks.o"
        src.write_text(assembly)
        subprocess.run([str(assembler), "-march=r5900", "-mabi=eabi", "-o", str(obj), str(src)],
                       check=True, capture_output=True)
        assembler = Path(assembler)
        if not assembler.name.endswith("as"):
            raise ValueError("assembler name must end in as")
        objcopy = os.environ.get("SOTC_EE_OBJCOPY", str(assembler.with_name(assembler.name[:-2] + "objcopy")))
        subprocess.run([objcopy, "--remove-section=.MIPS.abiflags", "--remove-section=.reginfo", str(obj)],
                       check=True, capture_output=True)
        linked = link_object(obj.read_bytes(), {".text": c.code, ".data": c.code + c.code_size - 32,
                                               ".bss": c.code + c.code_size - 16})
    if any(p.address < c.code or p.address + len(p.data) > c.code + c.code_size for p in linked.payloads):
        raise ValueError("hook code exceeds reserved extent")
    return linked


def build(c, evidence, *, assembler=None):
    verify(c, evidence)
    assembly = render(c)
    linked = _assemble(c, assembly, assembler or os.environ.get("SOTC_EE_AS", "mips64r5900el-ps2-elf-as"))
    expected, patches = guard_expectations(c), []
    for name, site in CALLS.items():
        symbol = "hook_submit" if name.startswith("submit_") else f"hook_{name}"
        patches.append(WordPatch(c.g + site, expected[c.g + site], _jump(linked.exports[symbol], True)))
    for site, symbol in ((0x21020, "hook_refresh"),) + tuple((site, f"hook_keep_{i}") for i, (site, _) in enumerate(EVICTIONS)):
        patches.append(WordPatch(c.g + site, expected[c.g + site], _jump(linked.exports[symbol])))
        patches.append(WordPatch(c.g + site + 4, expected[c.g + site + 4], 0))
    return Build(assembly, linked, tuple(patches))
