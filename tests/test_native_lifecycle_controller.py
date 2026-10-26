"""Offline controller qualification with actual lifecycle and registry bridge."""

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


class NativeControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("host C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="native-controller-")
        cls.binary = Path(cls.temp.name) / "controller"
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
                *(
                    str(SOURCE / name)
                    for name in (
                        "lifecycle.c",
                        "bridge.c",
                        "controller.c",
                        "controller_test.c",
                    )
                ),
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_scenarios(self):
        for scenario in (
            "normal",
            "death",
            "replacement",
            "failed-visual",
            "unknown",
            "intrinsics",
            "preparation",
            "delayed-cleanup",
            "empty-failure",
            "adoption",
            "active-inventory",
            "building-cancellation",
            "cancellation-faults",
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [str(self.binary), scenario],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.stdout.strip(), "ok")

    def test_ee_object(self):
        compiler = Path(os.environ.get("SOTC_EE_CC", EE))
        if not compiler.is_file():
            self.skipTest("PS2 EE compiler unavailable")
        output = Path(self.temp.name) / "controller.o"
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
                str(SOURCE / "controller.c"),
                "-o",
                str(output),
            ],
            check=True,
        )
        data = output.read_bytes()
        self.assertEqual(data[:7], b"\x7fELF\x01\x01\x01")
        self.assertEqual(struct.unpack_from("<H", data, 18)[0], 8)
        flags = struct.unpack_from("<I", data, 36)[0]
        self.assertEqual(flags & 0x00FF0000, 0x00920000)
        self.assertEqual(flags & 0x0000F000, 0x00004000)
        nm = str(compiler).removesuffix("gcc") + "nm"
        symbols = subprocess.run(
            [nm, "-u", str(output)], check=True, capture_output=True, text=True
        ).stdout
        for forbidden in ("malloc", "calloc", "realloc", "free", "memset", "memcpy"):
            self.assertNotIn(forbidden, symbols)


if __name__ == "__main__":
    unittest.main()
