"""Authored render bank only: synthetic host RAM and freestanding EE compilation."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from local_config import ee_tool

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "render_state"
EE = ee_tool("gcc")


class RenderStateBankTests(unittest.TestCase):
    def test_host_sanitizers(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("host compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="render-bank-") as tmp:
            binary = Path(tmp) / "test-bank"
            subprocess.run([
                cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-O1", "-g", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                "-fsanitize=address,undefined", str(SOURCE / "bank.c"),
                str(SOURCE / "test_bank.c"), "-o", str(binary),
            ], check=True)
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
            result = subprocess.run([str(binary)], check=True, env=env,
                                    capture_output=True, text=True)
            self.assertIn("max_ranges=1024 union_bytes=80", result.stdout)

    def test_freestanding_ee(self):
        cc = Path(os.environ.get("SOTC_EE_CC", str(EE)))
        if not cc.is_file():
            self.skipTest("PS2 EE compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="render-bank-ee-") as tmp:
            obj = Path(tmp) / "bank.o"
            subprocess.run([
                str(cc), "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                "-mabi=eabi", "-mlong32", "-mgp64", "-march=r5900", "-G0",
                "-mno-abicalls", "-fno-pic", "-ffreestanding", "-fno-builtin",
                "-fstack-usage", "-c", str(SOURCE / "bank.c"), "-o", str(obj),
            ], check=True)
            prefix = str(cc).removesuffix("gcc")
            undefined = subprocess.run([prefix + "nm", "-u", str(obj)], check=True,
                                       capture_output=True, text=True).stdout
            self.assertEqual(undefined.strip(), "")
            sections = subprocess.run([prefix + "size", "-A", str(obj)], check=True,
                                      capture_output=True, text=True).stdout
            for line in sections.splitlines():
                fields = line.split()
                if fields and fields[0] in (".bss", ".data"):
                    self.assertEqual(int(fields[1]), 0)
            disassembly = subprocess.run([prefix + "objdump", "-dr", str(obj)],
                                         check=True, capture_output=True, text=True).stdout
            for line in disassembly.splitlines():
                fields = line.split("\t")
                if len(fields) >= 3 and fields[2].split():
                    mnemonic = fields[2].split()[0]
                    self.assertFalse(mnemonic.endswith((".s", ".d")), line)
                    self.assertNotIn(mnemonic, ("lwc1", "swc1", "ldc1", "sdc1", "mtc1", "mfc1"))
            for line in obj.with_suffix(".su").read_text().splitlines():
                self.assertLessEqual(int(line.split("\t")[1]), 512, line)


if __name__ == "__main__":
    unittest.main()
