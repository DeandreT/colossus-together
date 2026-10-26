"""Authored horse-call policy using synthetic lifetimes and transactions only."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from local_config import ee_tool


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "horse_call"


@pytest.mark.parametrize("sanitize", [False, True])
def test_host_policy(tmp_path, sanitize):
    compiler = shutil.which("cc")
    if not compiler:
        pytest.skip("host C compiler unavailable")
    executable = tmp_path / "test-call"
    flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-no-pie"] if sanitize else []
    subprocess.run(
        [compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", *flags,
         str(SOURCE / "call.c"), str(SOURCE / "test_call.c"), "-o", str(executable)],
        check=True,
    )
    subprocess.run(
        [str(executable)], check=True,
        env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1"},
    )


def test_optional_ee_compile(tmp_path):
    compiler = ee_tool("gcc")
    if not shutil.which(str(compiler)):
        pytest.skip("optional EE compiler unavailable")
    subprocess.run(
        [str(compiler), "-std=c99", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
         "-c", str(SOURCE / "call.c"), "-o", str(tmp_path / "call.o")],
        check=True,
    )
