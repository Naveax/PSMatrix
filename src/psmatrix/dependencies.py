from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .util import read_json

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")
_MAX_NATIVE = 256
_MAX_MODULES = 512


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


def load_dependency_lock(path: Path) -> DependencyLock:
    path = path.resolve()
    if not path.is_file():
        raise DependencyError(f"Dependency lockfile not found: {path}")
    raw = path.read_bytes()
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
        if not isinstance(args, list) or not all(isinstance(arg, str) and "\x00" not in arg for arg in args):
            raise DependencyError(f"version_args for {name} must be an array of strings")
        if len(args) > 32 or sum(len(arg.encode("utf-8")) for arg in args) > 8192:
            raise DependencyError(f"version_args for {name} exceed limits")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 1024:
            raise DependencyError(f"version_pattern for {name} is required and must be <=1024 characters")
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
            raise DependencyError(f"version_pattern for {name} must contain a capture group")
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
