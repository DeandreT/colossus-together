"""Optional real offline binutils build; set SOTC_EE_AS to the EE assembler."""

import os
import shutil
import struct
import unittest

from injection.generator import (
    FREE_CALL_OFFSET,
    IOS_FREE_OFFSET,
    SITES,
    Config,
    build,
    guard_expectations,
)

ASSEMBLER = os.environ.get("SOTC_EE_AS") or shutil.which("mips64r5900el-ps2-elf-as")


@unittest.skipUnless(ASSEMBLER, "EE binutils not configured")
class BuildTests(unittest.TestCase):
    def test_character_guard_distinguishes_s0_and_s4_save_slots(self):
        _, start, guards = SITES["script_char"]
        self.assertEqual(start + 0x14, 0x832EC)
        self.assertEqual(guards[0x14], 0xFFB002C0)
        self.assertEqual(guards[0x18], 0xFFB402E0)
        self.assertEqual(guards[0x24], 0x00C0802D)

    def test_constructor_and_final_free_hooks_do_not_replace_delete_owner(self):
        config = Config(
            0x100000,
            0x500000,
            0x900000,
            0x1400000,
            0x1500000,
            0x1510000,
            capture_delete_requests=False,
        )
        expected = guard_expectations(config)
        delete_entry = config.k + SITES["delete_request"][1]
        self.assertNotIn(delete_entry, expected)
        words = {address: word for address, (word, _) in expected.items()}
        result = build(config, words, assembler=ASSEMBLER)
        self.assertEqual(len(result.patches), 5)
        self.assertNotIn(delete_entry, {p.address for p in result.patches})
        self.assertNotIn("hook_delete_request", result.linked.exports)
        self.assertIn("hook_final_free_allocation", result.linked.exports)
        final_hook = result.assembly.split("hook_final_free_allocation:", 1)[1]
        self.assertIn("addiu $t7, $zero, 4", final_hook)

    def test_real_elf_link_and_trampolines(self):
        config = Config(0x100000, 0x500000, 0x900000, 0x1400000, 0x1500000, 0x1510000)
        words = {
            address: word for address, (word, _) in guard_expectations(config).items()
        }
        result = build(config, words, assembler=ASSEMBLER)
        text = next(
            payload for payload in result.linked.payloads if payload.section == ".text"
        )
        self.assertLess(len(text.data), 0x3000)
        self.assertEqual(len(result.patches), 7)
        for name, (module, offset, guards) in SITES.items():
            self.assertIn(struct.pack("<II", guards[0], guards[4]), text.data)
            address = getattr(config, module) + offset
            patch = next(patch for patch in result.patches if patch.address == address)
            self.assertEqual(patch.expected, guards[0])
            self.assertEqual(
                (patch.replacement & 0x3FFFFFF) << 2,
                result.linked.exports[f"hook_{name}"],
            )
        free_call = next(
            p for p in result.patches if p.address == config.k + FREE_CALL_OFFSET
        )
        self.assertEqual(
            free_call.expected, 0x0C000000 | ((config.k + IOS_FREE_OFFSET) >> 2)
        )
        self.assertEqual(free_call.replacement >> 26, 3)
        self.assertEqual(
            (free_call.replacement & 0x3FFFFFF) << 2,
            result.linked.exports["hook_final_free_allocation"],
        )
        self.assertNotIn(
            config.k + FREE_CALL_OFFSET + 4, {p.address for p in result.patches}
        )
        # No FPU opcode can be introduced by macros or relocation processing.
        for (word,) in struct.iter_unpack("<I", text.data):
            self.assertNotIn(word >> 26, (0x11, 0x31, 0x35, 0x39, 0x3D))


if __name__ == "__main__":
    unittest.main()
