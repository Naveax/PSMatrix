from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PSMatrixError
from .util import read_json, sha256_file

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RESERVED_ENV = {
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "PSMODULEPATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "IFS",
    "ENV",
    "BASH_ENV",
    "SHELLOPTS",
    "CDPATH",
}
_RESERVED_PREFIXES = ("PSMATRIX_", "LD_", "DYLD_", "DOTNET_", "XDG_")
_MAX_VALUE_BYTES = 64 * 1024
_MAX_STDIN_BYTES = 8 * 1024 * 1024
_MAX_ARGUMENTS = 4096
_MAX_FIXTURES = 1024
_MAX_HOOKS = 64


class RunConfigurationError(PSMatrixError):
    """Raised when script inputs are malformed or unsafe."""


@dataclass(frozen=True)
class FixtureSpec:
    source: Path
    destination: Path
    sha256: str | None = None


@dataclass(frozen=True)
class HookSpec:
    source: Path
    phase: str
    sha256: str


@dataclass
class ExecutionProfile:
    arguments: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)
    stdin_data: bytes | None = None
    stdin_source: str | None = None
    fixtures: list[FixtureSpec] = field(default_factory=list)
    setup: list[HookSpec] = field(default_factory=list)
    teardown: list[HookSpec] = field(default_factory=list)
    lockfile: Path | None = None
    manifest: Path | None = None

    def redacted_report(self) -> dict[str, Any]:
        return {
            "arguments": {
                "count": len(self.arguments),
                "sha256": _json_hash(self.arguments),
            },
            "parameters": [
                {"name": name, "type": type(value).__name__, "sha256": _json_hash(value)}
                for name, value in sorted(self.parameters.items())
            ],
            "environment": [
                {"name": name, "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
                for name, value in sorted(self.environment.items())
            ],
            "stdin": {
                "present": self.stdin_data is not None,
                "bytes": len(self.stdin_data or b""),
                "sha256": hashlib.sha256(self.stdin_data).hexdigest() if self.stdin_data is not None else None,
                "source": self.stdin_source,
            },
            "fixtures": [
                {
                    "source": str(item.source),
                    "destination": item.destination.as_posix(),
                    "sha256": item.sha256 or _path_digest(item.source),
                }
                for item in self.fixtures
            ],
            "hooks": {
                "setup": [
                    {"source": str(item.source), "sha256": item.sha256} for item in self.setup
                ],
                "teardown": [
                    {"source": str(item.source), "sha256": item.sha256} for item in self.teardown
                ],
            },
            "lockfile": str(self.lockfile) if self.lockfile else None,
            "manifest": str(self.manifest) if self.manifest else None,
        }


def _json_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _path_digest(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    digest = hashlib.sha256()
    for current, dirs, files in os.walk(path, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
        for name in sorted(files):
            item = current_path / name
            if item.is_symlink():
                continue
            relative = item.relative_to(path).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            file_hash = bytes.fromhex(sha256_file(item))
            digest.update(file_hash)
    return digest.hexdigest()


def _validate_environment(values: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_name, raw_value in values.items():
        name = str(raw_name)
        upper = name.upper()
        if not _ENV_NAME_RE.fullmatch(name):
            raise RunConfigurationError(f"Invalid environment variable name: {name!r}")
        if upper in _RESERVED_ENV or any(upper.startswith(prefix) for prefix in _RESERVED_PREFIXES):
            raise RunConfigurationError(f"Environment variable is reserved by the sandbox: {name}")
        if not isinstance(raw_value, str):
            raise RunConfigurationError(f"Environment value for {name} must be a string")
        if "\x00" in raw_value:
            raise RunConfigurationError(f"Environment value for {name} contains a NUL byte")
        if len(raw_value.encode("utf-8")) > _MAX_VALUE_BYTES:
            raise RunConfigurationError(f"Environment value for {name} exceeds {_MAX_VALUE_BYTES} bytes")
        result[name] = raw_value
    return result


def _validate_parameters(values: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_name, value in values.items():
        name = str(raw_name)
        if not _PARAM_NAME_RE.fullmatch(name):
            raise RunConfigurationError(f"Invalid PowerShell parameter name: {name!r}")
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise RunConfigurationError(f"Parameter {name} is not JSON serializable: {exc}") from exc
        if len(encoded) > _MAX_VALUE_BYTES:
            raise RunConfigurationError(f"Parameter {name} exceeds {_MAX_VALUE_BYTES} bytes")
        result[name] = value
    return result


def _validate_arguments(values: list[Any]) -> list[str]:
    if len(values) > _MAX_ARGUMENTS:
        raise RunConfigurationError(f"Too many positional arguments: {len(values)}")
    result: list[str] = []
    total = 0
    for value in values:
        if not isinstance(value, str):
            raise RunConfigurationError("Positional arguments must be strings")
        if "\x00" in value:
            raise RunConfigurationError("Positional argument contains a NUL byte")
        total += len(value.encode("utf-8"))
        if total > _MAX_VALUE_BYTES * 4:
            raise RunConfigurationError("Combined positional arguments are too large")
        result.append(value)
    return result


def _safe_destination(value: str) -> Path:
    normalized = value.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if not pure.parts or pure.is_absolute() or ".." in pure.parts:
        raise RunConfigurationError(f"Unsafe fixture destination: {value!r}")
    if pure.parts[0] == ".psmatrix-internal":
        raise RunConfigurationError("Fixtures cannot target .psmatrix-internal")
    if any("\x00" in part for part in pure.parts):
        raise RunConfigurationError(f"Unsafe fixture destination: {value!r}")
    return Path(*pure.parts)


def _reject_symlink_components(path: Path, *, kind: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                raise RunConfigurationError(f"{kind} path contains a symlink: {current}")
        except OSError as exc:
            raise RunConfigurationError(f"Unable to inspect {kind} path {current}: {exc}") from exc


def _resolve_existing(base: Path, value: str, *, kind: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = candidate.absolute()
    _reject_symlink_components(candidate, kind=kind)
    try:
        candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise RunConfigurationError(f"{kind} not found: {candidate}") from exc
    return candidate


def _parse_fixture(base: Path, raw: Any) -> FixtureSpec:
    if isinstance(raw, str):
        source_value = raw
        destination_value = Path(raw).name
        expected_hash = None
    elif isinstance(raw, dict):
        source_value = raw.get("source")
        destination_value = raw.get("destination") or (Path(str(source_value)).name if source_value else None)
        expected_hash = raw.get("sha256")
    else:
        raise RunConfigurationError("Fixture entries must be strings or objects")
    if not isinstance(source_value, str) or not isinstance(destination_value, str):
        raise RunConfigurationError("Fixture source/destination must be strings")
    source = _resolve_existing(base, source_value, kind="Fixture")
    if not (source.is_file() or source.is_dir()):
        raise RunConfigurationError(f"Fixture must be a regular file or directory: {source}")
    if source.is_dir():
        for current, dirs, files in os.walk(source, followlinks=False):
            current_path = Path(current)
            for name in list(dirs) + list(files):
                item = current_path / name
                if item.is_symlink():
                    raise RunConfigurationError(f"Fixture tree contains a symlink: {item}")
    destination = _safe_destination(destination_value)
    if expected_hash is not None:
        if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
            raise RunConfigurationError("Fixture SHA-256 must be 64 hexadecimal characters")
        actual = _path_digest(source)
        if actual.lower() != expected_hash.lower():
            raise RunConfigurationError(
                f"Fixture SHA-256 mismatch for {source}: expected {expected_hash.lower()}, got {actual}"
            )
        expected_hash = expected_hash.lower()
    return FixtureSpec(source=source, destination=destination, sha256=expected_hash)


def _parse_hook(base: Path, raw: Any, phase: str) -> HookSpec:
    expected_hash = None
    if isinstance(raw, str):
        path_value = raw
    elif isinstance(raw, dict):
        path_value = raw.get("path")
        expected_hash = raw.get("sha256")
    else:
        raise RunConfigurationError(f"{phase} hooks must be strings or objects")
    if not isinstance(path_value, str):
        raise RunConfigurationError(f"{phase} hook path must be a string")
    source = _resolve_existing(base, path_value, kind=f"{phase} hook")
    if not source.is_file() or source.suffix.lower() != ".ps1":
        raise RunConfigurationError(f"{phase} hook must be a .ps1 file: {source}")
    actual_hash = sha256_file(source)
    if expected_hash is not None:
        if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
            raise RunConfigurationError(f"{phase} hook SHA-256 must be 64 hexadecimal characters")
        if actual_hash != expected_hash.lower():
            raise RunConfigurationError(
                f"{phase} hook SHA-256 mismatch for {source}: expected {expected_hash.lower()}, got {actual_hash}"
            )
    return HookSpec(source=source, phase=phase, sha256=actual_hash)


def _load_stdin(base: Path, raw: Any) -> tuple[bytes | None, str | None]:
    if raw is None:
        return None, None
    if isinstance(raw, str):
        data = raw.encode("utf-8")
        source = "manifest:text"
    elif isinstance(raw, dict):
        has_text = "text" in raw
        has_file = "file" in raw
        if has_text == has_file:
            raise RunConfigurationError("stdin must contain exactly one of text or file")
        if has_text:
            if not isinstance(raw["text"], str):
                raise RunConfigurationError("stdin.text must be a string")
            data = raw["text"].encode("utf-8")
            source = "manifest:text"
        else:
            if not isinstance(raw["file"], str):
                raise RunConfigurationError("stdin.file must be a string")
            path = _resolve_existing(base, raw["file"], kind="stdin file")
            if not path.is_file():
                raise RunConfigurationError(f"stdin file is not a regular file: {path}")
            data = path.read_bytes()
            source = str(path)
    else:
        raise RunConfigurationError("stdin must be a string or object")
    if len(data) > _MAX_STDIN_BYTES:
        raise RunConfigurationError(f"stdin exceeds {_MAX_STDIN_BYTES} bytes")
    return data, source


def _sidecar(source: Path) -> Path:
    return source.with_name(source.name + ".psmatrix.json")


def resolve_execution_profile(
    source: Path,
    *,
    cli_arguments: tuple[str, ...] = (),
    cli_parameters: tuple[tuple[str, Any], ...] = (),
    cli_environment: tuple[tuple[str, str], ...] = (),
    cli_stdin_data: bytes | None = None,
    cli_stdin_source: str | None = None,
    cli_fixtures: tuple[tuple[str, str | None], ...] = (),
    cli_setup: tuple[str, ...] = (),
    cli_teardown: tuple[str, ...] = (),
    cli_lockfile: str | None = None,
) -> ExecutionProfile:
    source = source.resolve()
    base = source.parent
    manifest = _sidecar(source)
    run: dict[str, Any] = {}
    if manifest.exists():
        _reject_symlink_components(manifest, kind="Run manifest")
    if manifest.is_file():
        payload = read_json(manifest)
        raw_run = payload.get("run", {})
        if not isinstance(raw_run, dict):
            raise RunConfigurationError(f"run section must be an object: {manifest}")
        run = raw_run

    raw_arguments = run.get("arguments", [])
    if not isinstance(raw_arguments, list):
        raise RunConfigurationError("run.arguments must be an array")
    arguments = _validate_arguments(list(raw_arguments) + list(cli_arguments))
    raw_parameters = run.get("parameters", {})
    if not isinstance(raw_parameters, dict):
        raise RunConfigurationError("run.parameters must be an object")
    parameters = dict(raw_parameters)
    parameters.update(dict(cli_parameters))
    parameters = _validate_parameters(parameters)

    raw_environment = run.get("environment", {})
    if not isinstance(raw_environment, dict):
        raise RunConfigurationError("run.environment must be an object")
    environment = dict(raw_environment)
    environment.update(dict(cli_environment))
    environment = _validate_environment(environment)

    stdin_data, stdin_source = _load_stdin(base, run.get("stdin"))
    if cli_stdin_data is not None:
        if len(cli_stdin_data) > _MAX_STDIN_BYTES:
            raise RunConfigurationError(f"stdin exceeds {_MAX_STDIN_BYTES} bytes")
        stdin_data = cli_stdin_data
        stdin_source = cli_stdin_source or "cli"

    fixture_values = run.get("fixtures", [])
    if not isinstance(fixture_values, list):
        raise RunConfigurationError("run.fixtures must be an array")
    fixtures = [_parse_fixture(base, item) for item in fixture_values]
    for source_value, destination_value in cli_fixtures:
        fixtures.append(
            _parse_fixture(
                Path.cwd(),
                {"source": source_value, "destination": destination_value or Path(source_value).name},
            )
        )
    if len(fixtures) > _MAX_FIXTURES:
        raise RunConfigurationError(f"Too many fixtures: {len(fixtures)}")
    destinations: set[str] = set()
    for fixture in fixtures:
        key = fixture.destination.as_posix().casefold()
        if key in destinations:
            raise RunConfigurationError(f"Duplicate fixture destination: {fixture.destination}")
        destinations.add(key)

    raw_setup = run.get("setup", [])
    raw_teardown = run.get("teardown", [])
    if not isinstance(raw_setup, list) or not isinstance(raw_teardown, list):
        raise RunConfigurationError("run.setup and run.teardown must be arrays")
    setup = [_parse_hook(base, item, "setup") for item in raw_setup]
    teardown = [_parse_hook(base, item, "teardown") for item in raw_teardown]
    setup.extend(_parse_hook(Path.cwd(), item, "setup") for item in cli_setup)
    teardown.extend(_parse_hook(Path.cwd(), item, "teardown") for item in cli_teardown)
    if len(setup) > _MAX_HOOKS or len(teardown) > _MAX_HOOKS:
        raise RunConfigurationError("Too many setup/teardown hooks")

    lock_value = cli_lockfile if cli_lockfile is not None else run.get("lockfile")
    lockfile: Path | None = None
    if lock_value is not None:
        if not isinstance(lock_value, str):
            raise RunConfigurationError("run.lockfile must be a string")
        lock_base = Path.cwd() if cli_lockfile is not None else base
        lockfile = _resolve_existing(lock_base, lock_value, kind="Dependency lockfile")
        if not lockfile.is_file():
            raise RunConfigurationError(f"Dependency lockfile is not a file: {lockfile}")
    else:
        default_lock = base / "psmatrix.lock.json"
        if default_lock.exists():
            lockfile = _resolve_existing(base, "psmatrix.lock.json", kind="Dependency lockfile")
            if not lockfile.is_file():
                raise RunConfigurationError(f"Dependency lockfile is not a file: {lockfile}")

    return ExecutionProfile(
        arguments=arguments,
        parameters=parameters,
        environment=environment,
        stdin_data=stdin_data,
        stdin_source=stdin_source,
        fixtures=fixtures,
        setup=setup,
        teardown=teardown,
        lockfile=lockfile,
        manifest=manifest if manifest.is_file() else None,
    )


def materialize_fixtures(workspace: Path, fixtures: list[FixtureSpec]) -> list[dict[str, Any]]:
    staged: list[dict[str, Any]] = []
    root = workspace.resolve()
    for fixture in fixtures:
        destination = workspace / fixture.destination
        _reject_symlink_components(destination.parent, kind="Fixture destination")
        resolved_parent = destination.parent.resolve()
        if resolved_parent != root and root not in resolved_parent.parents:
            raise RunConfigurationError(f"Fixture destination escaped workspace: {fixture.destination}")
        if destination.is_symlink():
            raise RunConfigurationError(f"Fixture destination is a symlink: {fixture.destination}")
        if destination.exists():
            if _path_digest(destination) != _path_digest(fixture.source):
                raise RunConfigurationError(f"Fixture destination collision: {fixture.destination}")
        elif fixture.source.is_dir():
            _copy_tree_no_links(fixture.source, destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(fixture.source, destination, follow_symlinks=False)
        staged.append(
            {
                "source": str(fixture.source),
                "destination": fixture.destination.as_posix(),
                "sha256": _path_digest(destination),
            }
        )
    return staged


def stage_hooks(workspace: Path, hooks: list[HookSpec], phase: str) -> list[Path]:
    internal_root = workspace / ".psmatrix-internal"
    if internal_root.exists():
        _reject_symlink_components(internal_root, kind="Internal hook staging")
        if not internal_root.is_dir():
            raise RunConfigurationError(f"Internal staging path is not a directory: {internal_root}")
    destination_root = internal_root / "hooks" / phase
    if destination_root.exists():
        _reject_symlink_components(destination_root, kind="Internal hook staging")
    destination_root.mkdir(parents=True, exist_ok=True)
    result: list[Path] = []
    for index, hook in enumerate(hooks):
        destination = destination_root / f"{index:03d}-{hook.sha256[:12]}-{hook.source.name}"
        shutil.copy2(hook.source, destination, follow_symlinks=False)
        destination.chmod(0o644)
        result.append(destination)
    return result


def _copy_tree_no_links(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            item = current_path / name
            if item.is_symlink():
                raise RunConfigurationError(f"Fixture tree contains a symlink: {item}")
            shutil.copy2(item, target_dir / name, follow_symlinks=False)
