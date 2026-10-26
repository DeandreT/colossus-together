"""Offline host, sanitizer and freestanding EE checks for the pure planner."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from local_config import ee_tool

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "streaming"
EE = ee_tool("gcc")


class StreamingPlannerTests(unittest.TestCase):
    def test_host(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("host C compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="streaming-planner-") as temp:
            for sanitizer in (False, True):
                exe = Path(temp) / ("sanitized" if sanitizer else "planner")
                command = [
                    cc,
                    "-std=c99",
                    "-O1" if sanitizer else "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    str(SOURCE / "planner.c"),
                    str(SOURCE / "test_planner.c"),
                    "-o",
                    str(exe),
                ]
                if sanitizer:
                    command += [
                        "-fsanitize=address,undefined",
                        "-fno-omit-frame-pointer",
                    ]
                subprocess.run(command, check=True, capture_output=True, text=True)
                result = subprocess.run(
                    [str(exe)],
                    check=True,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"},
                )
                self.assertIn("streaming planner checks passed", result.stdout)

    @unittest.skipUnless(EE.exists(), "local EE cross compiler not available")
    def test_ee_freestanding_integer_only(self):
        with tempfile.TemporaryDirectory(prefix="streaming-planner-ee-") as temp:
            obj = Path(temp) / "planner.o"
            subprocess.run(
                [
                    str(EE),
                    "-std=c99",
                    "-O2",
                    "-G0",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-tree-loop-distribute-patterns",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-c",
                    str(SOURCE / "planner.c"),
                    "-o",
                    str(obj),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            nm = EE.with_name("mips64r5900el-ps2-elf-nm")
            undefined = subprocess.run(
                [str(nm), "-u", str(obj)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertEqual(undefined.strip(), "")
            dump = subprocess.run(
                [str(EE.with_name("mips64r5900el-ps2-elf-objdump")), "-d", str(obj)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertNotRegex(
                dump, r"\b(?:lwc1|swc1|ldc1|sdc1|mtc1|mfc1|ctc1|cfc1)\b"
            )
            self.assertNotRegex(dump, r"\b(?:add|sub|mul|div|cvt|trunc|sqrt)\.[sdw]\b")


if __name__ == "__main__":
    unittest.main()
