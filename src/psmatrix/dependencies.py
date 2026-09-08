from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")
_MAX_NATIVE = 256
_MAX_MODULES = 512
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class DependencyError(PSMatrixError):
    """Raised when a dependency lockfile is invalid or cannot be satisfied."""


@dataclass(frozen=True)
class ModuleLock:
    name: str
    version: str
    sha256: str
    require_verified: bool = False


@dataclass(frozen=True)
class NativeLock:
    name: str
    command: str
    version_args: tuple[str, ...]
    version_pattern: str
    expected_version: str
    required: bool = True


@dataclass(frozen=True)
class DependencyLock:
    path: Path
    sha256: str
    modules: tuple[ModuleLock, ...]
    native: tuple[NativeLock, ...]

    def normalized(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "powershell_modules": [
                {
                    "name": item.name,
                    "version": item.version,
                    "sha256": item.sha256,
                    "require_verified": item.require_verified,
                }
                for item in self.modules
            ],
            "native_commands": [
                {
                    "name": item.name,
                    "command": item.command,
                    "version_args": list(item.version_args),
                    "version_pattern": item.version_pattern,
                    "expected_version": item.expected_version,
                    "required": item.required,
                }
                for item in self.native
            ],
        }


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    try:
        return os.path.samestat(left, right)
    except (AttributeError, OSError, ValueError):
        return (
            getattr(left, "st_dev", None) == getattr(right, "st_dev", None)
            and getattr(left, "st_ino", None) == getattr(right, "st_ino", None)
            and getattr(left, "st_ino", 0) not in {0, None}
        )


def _reject_indirect_components(path: Path) -> Path:
    candidate = _lexical_absolute(path)
    current = Path(candidate.anchor) if candidate.anchor else Path()
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise DependencyError(
                f"Unable to inspect dependency lockfile path: {current}"
            ) from exc
        if _is_link_or_reparse(info):
            raise DependencyError(
                f"Dependency lockfile cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _read_direct_lock_bytes(path: Path) -> tuple[Path, bytes]:
    candidate = _reject_indirect_components(path)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise DependencyError(f"Dependency lockfile not found: {candidate}") from exc
    except OSError as exc:
        raise DependencyError(f"Unable to inspect dependency lockfile: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise DependencyError(
            f"Dependency lockfile must be a direct regular file: {candidate}"
        )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            opened = os.fstat(handle.fileno())
            current = candidate.lstat()
            if (
                _is_link_or_reparse(current)
                or not stat.S_ISREG(current.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or not _same_file(current, opened)
            ):
                raise DependencyError(
                    f"Dependency lockfile changed while opening: {candidate}"
                )
            raw = handle.read()
            opened_after = os.fstat(handle.fileno())
            current_after = candidate.lstat()
            if (
                _is_link_or_reparse(current_after)
                or not stat.S_ISREG(current_after.st_mode)
                or not _same_file(opened, opened_after)
                or not _same_file(current_after, opened_after)
                or int(opened.st_size) != int(opened_after.st_size)
                or int(opened.st_mtime_ns) != int(opened_after.st_mtime_ns)
            ):
                raise DependencyError(
                    f"Dependency lockfile changed while reading: {candidate}"
                )
    except DependencyError:
        raise
    except OSError as exc:
        raise DependencyError(f"Unable to read dependency lockfile: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise DependencyError(
            f"Unable to revalidate dependency lockfile: {candidate}"
        ) from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISREG(final.st_mode)
        or not _same_file(final, opened_after)
    ):
        raise DependencyError(f"Dependency lockfile changed after read: {candidate}")
    return candidate, raw


def load_dependency_lock(path: Path) -> DependencyLock:
    path, raw = _read_direct_lock_bytes(path)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyError(f"Invalid dependency lockfile JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise DependencyError("Dependency lockfile schema must be 1")

    raw_modules = payload.get("powershell_modules", [])
    raw_native = payload.get("native_commands", [])
    if not isinstance(raw_modules, list) or not isinstance(raw_native, list):
        raise DependencyError("Dependency lists must be arrays")
    if len(raw_modules) > _MAX_MODULES or len(raw_native) > _MAX_NATIVE:
        raise DependencyError("Dependency lockfile exceeds entry limits")

    modules: list[ModuleLock] = []
    module_keys: set[str] = set()
    for item in raw_modules:
        if not isinstance(item, dict):
            raise DependencyError("PowerShell module entries must be objects")
        name = item.get("name")
        version = item.get("version")
        digest = item.get("sha256")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise DependencyError(f"Invalid PowerShell module name: {name!r}")
        if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
            raise DependencyError(f"Invalid PowerShell module version: {version!r}")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise DependencyError(f"Invalid SHA-256 for module {name} {version}")
        key = name.casefold()
        if key in module_keys:
            raise DependencyError(f"Duplicate PowerShell module lock: {name}")
        module_keys.add(key)
        modules.append(
            ModuleLock(
                name=name,
                version=version,
                sha256=digest.lower(),
                require_verified=bool(item.get("require_verified", False)),
            )
        )

    native: list[NativeLock] = []
    native_keys: set[str] = set()
    for item in raw_native:
        if not isinstance(item, dict):
            raise DependencyError("Native command entries must be objects")
        name = item.get("name")
        command = item.get("command", name)
        args = item.get("version_args", ["--version"])
        pattern = item.get("version_pattern")
        expected = item.get("expected_version")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise DependencyError(f"Invalid native dependency name: {name!r}")
        if not isinstance(command, str) or not _COMMAND_RE.fullmatch(command):
            raise DependencyError(f"Invalid native dependency command: {command!r}")
        if not isinstance(args, list) or not all(
            isinstance(arg, str) and "\x00" not in arg for arg in args
        ):
            raise DependencyError(f"version_args for {name} must be an array of strings")
        if len(args) > 32 or sum(len(arg.encode("utf-8")) for arg in args) > 8192:
            raise DependencyError(f"version_args for {name} exceed limits")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 1024:
            raise DependencyError(
                f"version_pattern for {name} is required and must be <=1024 characters"
            )
        if not isinstance(expected, str) or not expected or len(expected) > 256:
            raise DependencyError(f"expected_version for {name} is required")
        python_pattern = re.sub(
            r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>",
            r"(?P<\1>",
            pattern,
        )
        try:
            compiled = re.compile(python_pattern)
        except re.error as exc:
            raise DependencyError(f"Invalid version_pattern for {name}: {exc}") from exc
        if compiled.groups < 1 and "version" not in compiled.groupindex:
            raise DependencyError(
                f"version_pattern for {name} must contain a capture group"
            )
        key = name.casefold()
        if key in native_keys:
            raise DependencyError(f"Duplicate native dependency lock: {name}")
        native_keys.add(key)
        native.append(
            NativeLock(
                name=name,
                command=command,
                version_args=tuple(args),
                version_pattern=pattern,
                expected_version=expected,
                required=bool(item.get("required", True)),
            )
        )

    return DependencyLock(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        modules=tuple(sorted(modules, key=lambda item: item.name.casefold())),
        native=tuple(sorted(native, key=lambda item: item.name.casefold())),
    )
