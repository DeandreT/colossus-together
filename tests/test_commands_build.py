"""Real R5900/EABI assembly, linking and delay slots when EE tools exist."""

import os
import shutil
import struct
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_commands_dispatch import configuration

from commands.generator import CALL_OFFSET, Target, build, guards, render

ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")
CC = shutil.which("cc")


def test_upgrade_matches_only_the_verified_previous_dispatcher():
    original = configuration()
    config = replace(
        original,
        code=original.code + 0x10000,
        mailbox=original.mailbox + 0x10000,
        previous_dispatch=original.code,
    )
    expected = guards(config)
    site = config.gamecore + CALL_OFFSET
    assert expected[site] == 0x0C000000 | (original.code >> 2)
    assembly = render(config, expected)
    assert "original_USB" in assembly
    bad = dict(expected)
    bad[site] = 0x0C000000 | (config.original_usb >> 2)
    with pytest.raises(ValueError, match="guard"):
        render(config, bad)
    with pytest.raises(ValueError, match="replacement storage"):
        replace(original, previous_dispatch=original.code)


@pytest.mark.skipif(not CC, reason="native C compiler unavailable")
def test_header_layout_with_native_c11_compiler():
    header = Path(__file__).resolve().parents[1] / "commands" / "mailbox.h"
    subprocess.run(
        [CC, "-std=c11", "-x", "c", "-fsyntax-only", "-"],
        input=f'#include "{header}"\n'.encode(),
        capture_output=True,
        check=True,
    )


@pytest.mark.skipif(
    not ASSEMBLER, reason="EE binutils unavailable; no emulator/toolchain installed"
)
@pytest.mark.parametrize(
    "target_stack,frame_callback",
    [
        (None, None),
        ((0x1600000, 0x4000), None),
        ((0x1600000, 0x8000), Target(0x130000, 0x610000)),
    ],
)
def test_real_r5900_eabi_object_and_preservation_opcodes(target_stack, frame_callback):
    config = configuration(target_stack=target_stack, frame_callback=frame_callback)
    result = build(config, guards(config), assembler=ASSEMBLER)
    # EF_MIPS_ABI_EABI64 and EF_MIPS_MACH_5900, not merely generic MIPS.
    flags = struct.unpack_from("<I", result.object_bytes, 36)[0]
    assert flags & 0xF000 == 0x4000
    assert flags & 0xFF0000 == 0x920000
    text = next(p.data for p in result.linked.payloads if p.section == ".text")
    words = [w[0] for w in struct.iter_unpack("<I", text)]
    table = (result.linked.exports["command_targets"] - config.code) // 4
    instructions = words[:table]
    # All control transfers have explicit, assembled NOP delay slots.
    transfers = []
    for i, word in enumerate(instructions):
        opcode = word >> 26
        if opcode in (2, 3, 4, 5) or (opcode == 0 and word & 63 in (8, 9)):
            transfers.append(word)
            assert instructions[i + 1] == 0
    assert transfers
    assert (0x08000000 | (config.original_usb >> 2)) in transfers
    # SQ/LQ opcodes, all FPR saves/restores and FCSR control transfers present.
    assert sum(w >> 26 == 0x1F for w in instructions) == 31
    assert sum(w >> 26 == 0x1E for w in instructions) == 31
    assert sum(w >> 26 == 0x39 for w in instructions) >= 32
    assert sum(w >> 26 == 0x31 for w in instructions) >= 32
    assert any(w >> 21 == (0x11 << 5 | 2) for w in instructions)  # CFC1
    assert any(w >> 21 == (0x11 << 5 | 6) for w in instructions)  # CTC1
    if target_stack is not None:
        calls = [i for i, word in enumerate(instructions) if word == 0x0320F809]
        assert len(calls) == (2 if frame_callback else 1)
        for jalr in calls:
            assert instructions[jalr - 1] == 0xFFB80040  # sd t8,64(sp)
            assert instructions[jalr + 2] == 0xDFB80040  # ld t8,64(sp)
            assert instructions[jalr + 3] == 0x0300E82D  # daddu sp,t8,zero
    assert result.initial_mailbox == bytes(96)
    assert len(result.patches) == 1
    patch = result.patches[0]
    assert patch.address == config.gamecore + CALL_OFFSET
    assert patch.expected == guards(config)[patch.address]
    assert patch.replacement == 0x0C000000 | (
        result.linked.exports["command_dispatch"] >> 2
    )
