from __future__ import annotations

import os
from pathlib import Path

POWERSHELL_SUFFIXES = {".ps1", ".psm1", ".psd1"}
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".psmatrix",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
}


def scan_powershell_files(root: Path) -> list[Path]:
    root = root.resolve()
    if root.is_file():
        return [root] if root.suffix.lower() in POWERSHELL_SUFFIXES else []

    result: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS)
        for name in sorted(files):
            path = Path(current) / name
            if path.suffix.lower() in POWERSHELL_SUFFIXES:
                result.append(path)
    return result
