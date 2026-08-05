from __future__ import annotations

import re
from dataclasses import dataclass

from .models import RuntimeSpec


@dataclass(frozen=True)
class Channel:
    name: str
    version: str
    description: str


@dataclass(frozen=True)
class ReleaseLine:
    family: str
    version: str
    lifecycle: str
    legacy_host: bool = False
    description: str = ""


# Channel aliases are intentionally separate from the exact historical catalog.
# Exact versions remain first-class and never depend on a mutable alias.
BUILTIN_CHANNELS: dict[str, Channel] = {
    "stable": Channel("stable", "7.6.4", "Current stable PowerShell line"),
    "lts": Channel("lts", "7.6.4", "Current LTS PowerShell line"),
    "previous-lts": Channel("previous-lts", "7.4.18", "Previous supported LTS line"),
    "previous": Channel("previous", "7.5.7", "Previous stable line"),
    "preview": Channel("preview", "7.7.0-preview.2", "Current preview line"),
}


# Last patch selected for each historical Core line. These entries describe the
# matrix contract; a target is not considered tested until that exact runtime is
# installed and health-probed on the active backend.
CORE_RELEASE_LINES: tuple[ReleaseLine, ...] = (
    ReleaseLine("6.0", "6.0.5", "eol", True, "PowerShell Core 6.0 final patch"),
    ReleaseLine("6.1", "6.1.6", "eol", True, "PowerShell Core 6.1 final patch"),
    ReleaseLine("6.2", "6.2.7", "eol", True, "PowerShell Core 6.2 final patch"),
    ReleaseLine("7.0", "7.0.13", "eol", True, "PowerShell 7.0 final patch"),
    ReleaseLine("7.1", "7.1.7", "eol", True, "PowerShell 7.1 final patch"),
    ReleaseLine("7.2", "7.2.24", "eol", False, "PowerShell 7.2 final patch"),
    ReleaseLine("7.3", "7.3.12", "eol", False, "PowerShell 7.3 final patch"),
    ReleaseLine("7.4", "7.4.18", "supported", False, "PowerShell 7.4 selected patch"),
    ReleaseLine("7.5", "7.5.7", "supported", False, "PowerShell 7.5 selected patch"),
    ReleaseLine("7.6", "7.6.4", "supported", False, "PowerShell 7.6 selected patch"),
)

_RELEASE_BY_VERSION = {release.version: release for release in CORE_RELEASE_LINES}


MATRICES: dict[str, tuple[str, ...]] = {
    "stable": (BUILTIN_CHANNELS["stable"].version,),
    "default": (
        BUILTIN_CHANNELS["previous-lts"].version,
        BUILTIN_CHANNELS["stable"].version,
    ),
    "supported": (
        BUILTIN_CHANNELS["previous-lts"].version,
        BUILTIN_CHANNELS["previous"].version,
        BUILTIN_CHANNELS["stable"].version,
    ),
    "current": (
        BUILTIN_CHANNELS["previous-lts"].version,
        BUILTIN_CHANNELS["previous"].version,
        BUILTIN_CHANNELS["stable"].version,
        BUILTIN_CHANNELS["preview"].version,
    ),
    "core-6": tuple(release.version for release in CORE_RELEASE_LINES if release.family.startswith("6.")),
    "core-7": tuple(release.version for release in CORE_RELEASE_LINES if release.family.startswith("7.")),
    "core-all": tuple(release.version for release in CORE_RELEASE_LINES),
}


_VERSION_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<label>[A-Za-z]+)(?:\.(?P<labelnum>\d+))?)?$"
)


def version_key(value: str) -> tuple[int, int, int, int, str, int]:
    """Return a deterministic key without importing a packaging dependency."""

    normalized = value.removeprefix("v")
    match = _VERSION_RE.fullmatch(normalized)
    if not match:
        return (0, 0, 0, 0, normalized, 0)
    label = (match.group("label") or "").lower()
    # Stable sorts after previews for the same numeric version.
    stable_rank = 1 if not label else 0
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch") or 0),
        stable_rank,
        label,
        int(match.group("labelnum") or 0),
    )


def release_metadata(version: str) -> dict[str, object]:
    release = _RELEASE_BY_VERSION.get(version.removeprefix("v"))
    if release is None:
        return {
            "family": ".".join(version.removeprefix("v").split(".")[:2]),
            "lifecycle": "unknown",
            "legacy_host": False,
            "description": "Exact user-selected runtime",
        }
    return {
        "family": release.family,
        "lifecycle": release.lifecycle,
        "legacy_host": release.legacy_host,
        "description": release.description,
    }


def resolve_runtime(value: str, arch: str, libc: str = "glibc") -> RuntimeSpec:
    channel = BUILTIN_CHANNELS.get(value.lower())
    if channel:
        return RuntimeSpec(
            version=channel.version,
            arch=arch,
            libc=libc,
            channel=channel.name,
        )
    return RuntimeSpec(version=value.removeprefix("v"), arch=arch, libc=libc)


def matrix_versions(name: str) -> list[str]:
    key = name.lower()
    try:
        values = MATRICES[key]
    except KeyError as exc:
        raise ValueError(f"Unknown matrix: {name}") from exc
    return list(dict.fromkeys(values))
