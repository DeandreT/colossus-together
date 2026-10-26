"""Offline, synthetic tests only: never connects to the game or reads assets."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from local_config import ee_tool

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native_lifecycle"
EE = ee_tool("gcc")


class NativeMetadataTests(unittest.TestCase):
    def test_synthetic_discovery(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("host C compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="native-metadata-") as temp:
            binary = Path(temp) / "metadata"
            subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                            "-O2", str(SOURCE / "metadata.c"),
                            str(SOURCE / "metadata_test.c"), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "ok")

    def test_ee_object(self):
        compiler = Path(os.environ.get("SOTC_EE_CC", EE))
        if not compiler.is_file():
            self.skipTest("PS2 EE compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="native-metadata-ee-") as temp:
            output = Path(temp) / "metadata.o"
            subprocess.run([str(compiler), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-mabi=eabi", "-mlong32", "-mgp64", "-march=r5900", "-G0",
                            "-mno-abicalls", "-fno-pic", "-O2", "-ffreestanding", "-fno-builtin",
                            "-c", str(SOURCE / "metadata.c"), "-o", str(output)], check=True)
            data = output.read_bytes()
            self.assertEqual(data[:7], b"\x7fELF\x01\x01\x01")
            self.assertEqual(struct.unpack_from("<H", data, 18)[0], 8)
            flags = struct.unpack_from("<I", data, 36)[0]
            self.assertEqual(flags & 0x00FF0000, 0x00920000)
            self.assertEqual(flags & 0x0000F000, 0x00004000)
            nm = str(compiler).removesuffix("gcc") + "nm"
            symbols = subprocess.run([nm, "-u", str(output)], check=True,
                                     capture_output=True, text=True).stdout
            # Standalone validator must have no external runtime/library imports.
            self.assertEqual(symbols.strip(), "")


if __name__ == "__main__":
    unittest.main()
