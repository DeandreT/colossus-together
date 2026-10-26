"""Offline C provider integration with sanitized native-layout fixtures."""

import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from runtime.xff import parse
from local_config import ee_tool, original_file

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "streaming"
EE = ee_tool("gcc")
ORIGINAL = original_file()


class ProviderTests(unittest.TestCase):
    @unittest.skipUnless((ORIGINAL / "KERNEL.XFF").exists() and (ORIGINAL / "GAMECORE.XFF").exists(),
                         "private original XFFs unavailable")
    def test_native_execution_identity_and_blocking_call_evidence(self):
        kernel = parse((ORIGINAL / "KERNEL.XFF").read_bytes())
        ti = kernel.index_of(".text")
        text = kernel.sections[ti].data

        def word(off):
            return struct.unpack_from("<I", text, off - 0x38)[0]

        self.assertEqual(word(0x1D850), 0x3C030000)  # getter LUI v1
        self.assertEqual(word(0x1D854), 0x03E00008)  # JR ra
        self.assertEqual(word(0x1D858), 0x8C620A10)  # LW v0,D_40FA0(v1)
        self.assertEqual(word(0x1D138), 0x3C020000)  # resume LUI v0
        self.assertEqual(word(0x1D144), 0xAC440A10)  # SW selected object a0
        self.assertEqual(word(0x1D4EC), 0x27BDFD40)  # cooperative save frame

        def references_at(module, offset):
            text_index = module.index_of(".text")
            return [module.symbol_name(info >> 8)
                    for table in module.reltables if table.target == text_index
                    for off, info, _saved, _extra in table.entries
                    if off == offset - 0x38]

        self.assertEqual(references_at(kernel, 0x36B0), ["WaitSema"])
        game = parse((ORIGINAL / "GAMECORE.XFF").read_bytes())
        self.assertEqual(references_at(game, 0x20258), ["iosMallocAlign"])

    def test_host_and_sanitizers(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("host C compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="streaming-provider-") as temp:
            for sanitize in (False, True):
                exe = Path(temp) / ("sanitized" if sanitize else "provider")
                command = [cc, "-std=c99", "-O1" if sanitize else "-O2", "-Wall", "-Wextra",
                           "-Werror", "-pedantic", "-ffp-contract=off", str(SOURCE / "provider.c"),
                           str(SOURCE / "planner.c"), str(SOURCE / "test_provider.c"), "-o", str(exe)]
                if sanitize:
                    command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
                subprocess.run(command, check=True, capture_output=True, text=True)
                result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
                self.assertRegex(result.stdout, r"provider checks passed; caller-owned storage=\d+ bytes")

    @unittest.skipUnless(EE.exists(), "local EE compiler unavailable")
    def test_ee_no_heap_or_unresolved_helpers(self):
        with tempfile.TemporaryDirectory(prefix="streaming-provider-ee-") as temp:
            objects = []
            for name in ("provider", "planner"):
                obj = Path(temp) / (name + ".o")
                subprocess.run([str(EE), "-std=c99", "-O2", "-G0", "-mabi=eabi", "-mno-abicalls", "-fno-pic", "-ffreestanding", "-fno-builtin",
                                "-fno-tree-loop-distribute-patterns", "-Wall", "-Wextra", "-Werror",
                                "-c", str(SOURCE / (name + ".c")), "-o", str(obj)],
                               check=True, capture_output=True, text=True)
                objects.append(obj)
            combined = Path(temp) / "combined.o"
            subprocess.run([str(EE.with_name("mips64r5900el-ps2-elf-ld")), "-m", "elf32lr5900", "-r",
                            *(str(obj) for obj in objects), "-o", str(combined)],
                           check=True, capture_output=True, text=True)
            nm = EE.with_name("mips64r5900el-ps2-elf-nm")
            result = subprocess.run([str(nm), "-u", str(combined)], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "")
            dump = subprocess.run([str(EE.with_name("mips64r5900el-ps2-elf-objdump")), "-d", str(objects[0])],
                                  check=True, capture_output=True, text=True).stdout
            self.assertIn("cvt.w.s", dump)  # same positive-containing conversion as G+221F4
            self.assertNotIn("ctc1", dump)  # no silent FCSR rounding-mode replacement
            probe = Path(temp) / "size.c"
            probe.write_text('#include "provider.h"\nchar sp_size_marker[sizeof(sp_provider)];\n')
            size_obj = Path(temp) / "size.o"
            subprocess.run([str(EE), "-G0", "-mabi=eabi", "-mno-abicalls", "-fno-pic", "-I", str(SOURCE), "-c", str(probe), "-o", str(size_obj)],
                           check=True, capture_output=True, text=True)
            sizes = subprocess.run([str(nm), "-S", str(size_obj)], check=True, capture_output=True, text=True).stdout
            match = re.search(r"\b([0-9a-fA-F]+)\s+[BC]\s+sp_size_marker", sizes)
            self.assertIsNotNone(match)
            self.assertLess(int(match[1], 16), 128 * 1024)


if __name__ == "__main__":
    unittest.main()
