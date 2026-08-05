from __future__ import annotations

import re
from typing import Any

_DESKTOP_RE = re.compile(r"^windows-powershell-(?P<version>4\.0|5\.0|5\.1)$")
_CORE_WINDOWS_RE = re.compile(
    r"^powershell-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)-"
    r"windows-(?P<arch>x64|x86|arm64)$"
)


def parse_windows_runtime_id(value: str) -> dict[str, Any] | None:
    desktop = _DESKTOP_RE.fullmatch(value)
    if desktop:
        return {
            "runtime_id": value,
            "family": "windows-powershell",
            "edition": "Desktop",
            "version": desktop.group("version"),
            "platform": "windows",
            "arch": "x64-or-x86",
        }
    core = _CORE_WINDOWS_RE.fullmatch(value)
    if core:
        return {
            "runtime_id": value,
            "family": "powershell-core",
            "edition": "Core",
            "version": core.group("version"),
            "platform": "windows",
            "arch": core.group("arch"),
        }
    return None


def is_exact_windows_runtime_id(value: str) -> bool:
    return parse_windows_runtime_id(value) is not None


def windows_runtime_version(value: str) -> str:
    parsed = parse_windows_runtime_id(value)
    if parsed is None:
        raise ValueError(f"Invalid exact Windows runtime id: {value}")
    return str(parsed["version"])
