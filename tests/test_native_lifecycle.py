"""Compile and exercise project-authored C only; no live integration."""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from local_config import ee_tool

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native_lifecycle"
EE = ee_tool("gcc")


class NativeLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("host C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="native-lifecycle-")
        cls.binary = Path(cls.temp.name) / "host"
        subprocess.run(
            [
                cc,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-DNL_HOST_TEST",
                "-O2",
                str(SOURCE / "lifecycle.c"),
                str(SOURCE / "test_harness.c"),
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_host_scenarios(self):
        for scenario in (
            "retire",
            "reused_child",
            "spawn",
            "guards",
            "failures",
            "addresses",
            "bounds",
            "cycles",
            "failed-build",
            "failed-build-callback",
            "failed-build-empty",
            "failed-build-guards",
            "cancel-build",
            "cancel-build-guards",
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [str(self.binary), scenario],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.stdout.strip(), "ok")

    def test_actual_ee_object(self):
        compiler = Path(os.environ.get("SOTC_EE_CC", EE))
        if not compiler.is_file():
            self.skipTest("PS2 EE compiler unavailable")
        output = Path(self.temp.name) / "lifecycle.o"
        subprocess.run(
            [
                str(compiler),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-mabi=eabi",
                "-mlong32",
                "-mgp64",
                "-march=r5900",
                "-G0",
                "-mno-abicalls",
                "-fno-pic",
                "-O2",
                "-ffreestanding",
                "-fno-builtin",
                "-c",
                str(SOURCE / "lifecycle.c"),
                "-o",
                str(output),
            ],
            check=True,
        )
        data = output.read_bytes()
        self.assertEqual(data[:7], b"\x7fELF\x01\x01\x01")
        self.assertEqual(struct.unpack_from("<H", data, 18)[0], 8)  # EM_MIPS
        flags = struct.unpack_from("<I", data, 36)[0]
        self.assertEqual(flags & 0x00FF0000, 0x00920000)  # R5900
        self.assertEqual(flags & 0x0000F000, 0x00004000)  # EABI64
        objdump = str(compiler).removesuffix("gcc") + "objdump"
        disassembly = subprocess.run(
            [objdump, "-dr", str(output)], check=True, capture_output=True, text=True
        ).stdout
        for symbol in (
            "begin_retire",
            "retire_failed_build",
            "cancel_build",
            "release_parent",
            "spawn_actor",
            "spawn_visual",
            "commit_active",
        ):
            self.assertIn(f"<{symbol}>:", disassembly)
        # No floating arithmetic is needed: do not accidentally emit NaN/FPU
        # instructions (including signaling comparisons) in this integer layer.
        for line in disassembly.splitlines():
            fields = line.split("\t")
            if len(fields) >= 3:
                mnemonic = fields[2].split()[0] if fields[2].split() else ""
                self.assertFalse(mnemonic.endswith((".s", ".d")), line)


if __name__ == "__main__":
    unittest.main()
