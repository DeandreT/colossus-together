"""Optional local tools and user-supplied inputs; never discover private files."""

import os
import shutil
from pathlib import Path


def ee_tool(name: str) -> Path:
    variable = "SOTC_EE_CC" if name == "gcc" else "SOTC_EE_AS" if name == "as" else None
    configured = os.environ.get(variable, "") if variable else ""
    executable = configured or f"mips64r5900el-ps2-elf-{name}"
    return Path(shutil.which(executable) or executable)


def original_file(name: str = "") -> Path:
    return Path(os.environ.get("SOTC_ORIGINAL_DIR", ".local-game-inputs")) / name
