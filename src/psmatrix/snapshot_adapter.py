from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .process import run_process
from .signing import canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope
from .util import utc_now_iso


class SnapshotError(PSMatrixError):
    """Raised when a hypervisor reset cannot be measured or trusted."""


_ALLOWED_PROVIDERS = {"hyper-v", "vmware", "virtualbox", "command-test"}
_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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


def _reject_indirect_components(path: Path, *, label: str) -> Path:
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
            raise SnapshotError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise SnapshotError(
                f"{label} cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SnapshotError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise SnapshotError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise SnapshotError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise SnapshotError(f"{label} must be a direct directory: {candidate}")
    return candidate


def _read_direct_file_bytes(path: Path, *, label: str) -> tuple[Path, bytes]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise SnapshotError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise SnapshotError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise SnapshotError(f"{label} must be a direct regular file: {candidate}")

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
                raise SnapshotError(f"{label} changed while opening: {candidate}")
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
                raise SnapshotError(f"{label} changed while reading: {candidate}")
    except SnapshotError:
        raise
    except OSError as exc:
        raise SnapshotError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise SnapshotError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISREG(final.st_mode)
        or not _same_file(final, opened_after)
    ):
        raise SnapshotError(f"{label} changed after read: {candidate}")
    return candidate, raw


def _command(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise SnapshotError(f"{label} must be a non-empty argument array")
    result = []
    for item in value:
        text = str(item)
        if not text or len(text) > 4096 or "\x00" in text:
            raise SnapshotError(f"{label} contains an invalid argument")
        result.append(text)
    return tuple(result)


def _run(command: list[str], *, cwd: Path, timeout: int) -> dict[str, Any]:
    execution = run_process(
        command,
        cwd,
        dict(os.environ),
        timeout_seconds=timeout,
        max_output_bytes=_MAX_COMMAND_OUTPUT_BYTES,
    )
    if execution.timed_out:
        raise SnapshotError(f"Snapshot command timed out after {timeout} seconds")
    if execution.resource_violation is not None:
        raise SnapshotError(
            f"Snapshot command violated execution bounds: {execution.resource_violation}"
        )
    return {
        "exit_code": execution.exit_code,
        "stdout": execution.stdout,
        "stderr": execution.stderr,
    }


def _digest_text(value: str) -> dict[str, Any]:
    raw = value.encode("utf-8", errors="replace")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


@dataclass(frozen=True)
class SnapshotAdapterConfig:
    adapter_id: str
    provider: str
    worker_id: str
    vm_id: str
    snapshot_id: str
    restore_command: tuple[str, ...]
    measure_command: tuple[str, ...]
    cwd: Path
    expected_after: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 600

    @classmethod
    def load(cls, path: Path) -> "SnapshotAdapterConfig":
        config_path, raw = _read_direct_file_bytes(
            path, label="Snapshot adapter configuration"
        )
        base = config_path.parent
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotError("Snapshot adapter configuration is invalid JSON") from exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise SnapshotError("Unsupported snapshot adapter configuration")
        cwd_raw = Path(str(value.get("cwd") or "."))
        cwd = _lexical_absolute(cwd_raw if cwd_raw.is_absolute() else base / cwd_raw)
        config = cls(
            adapter_id=str(value.get("adapter_id") or ""),
            provider=str(value.get("provider") or ""),
            worker_id=str(value.get("worker_id") or ""),
            vm_id=str(value.get("vm_id") or ""),
            snapshot_id=str(value.get("snapshot_id") or ""),
            restore_command=_command(value.get("restore_command"), "restore_command"),
            measure_command=_command(value.get("measure_command"), "measure_command"),
            cwd=cwd,
            expected_after=dict(value.get("expected_after") or {}),
            timeout_seconds=int(value.get("timeout_seconds") or 600),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.adapter_id or len(self.adapter_id) > 128:
            raise SnapshotError("Snapshot adapter identity is invalid")
        if self.provider not in _ALLOWED_PROVIDERS:
            raise SnapshotError("Unsupported snapshot provider")
        for value in (self.worker_id, self.vm_id, self.snapshot_id):
            if not value or len(value) > 256 or "\x00" in value:
                raise SnapshotError("Snapshot identity value is invalid")
        if not 10 <= self.timeout_seconds <= 3600:
            raise SnapshotError("Snapshot timeout is outside the supported range")
        if not isinstance(self.expected_after, dict) or len(self.expected_after) > 64:
            raise SnapshotError("Snapshot expected_after mapping is invalid")
        for path, expected in self.expected_after.items():
            if not isinstance(path, str) or not path or len(path) > 256 or any(not part for part in path.split(".")):
                raise SnapshotError("Snapshot expected_after path is invalid")
            if isinstance(expected, (dict, list)) or len(str(expected)) > 4096:
                raise SnapshotError("Snapshot expected_after value is invalid")
        _direct_directory(self.cwd, label="Snapshot working directory", create=True)

    def expand(self, command: tuple[str, ...], phase: str) -> list[str]:
        values = {
            "{worker_id}": self.worker_id,
            "{vm_id}": self.vm_id,
            "{snapshot_id}": self.snapshot_id,
            "{phase}": phase,
        }
        result = []
        for argument in command:
            text = argument
            for token, replacement in values.items():
                text = text.replace(token, replacement)
            result.append(text)
        return result


def _lookup(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise SnapshotError(f"Snapshot measurement is missing expected field: {path}")
        current = current[part]
    return current


def _expand_expected(config: SnapshotAdapterConfig) -> dict[str, Any]:
    tokens = {
        "{worker_id}": config.worker_id,
        "{vm_id}": config.vm_id,
        "{snapshot_id}": config.snapshot_id,
    }
    result: dict[str, Any] = {}
    for path, expected in config.expected_after.items():
        if isinstance(expected, str):
            text = expected
            for token, replacement in tokens.items():
                text = text.replace(token, replacement)
            result[path] = text
        else:
            result[path] = expected
    return result


class SnapshotAdapter:
    def __init__(self, config: SnapshotAdapterConfig):
        self.config = config

    def measure(self, phase: str) -> dict[str, Any]:
        cwd = _direct_directory(
            self.config.cwd, label="Snapshot working directory"
        )
        command = self.config.expand(self.config.measure_command, phase)
        result = _run(command, cwd=cwd, timeout=min(self.config.timeout_seconds, 120))
        if result["exit_code"] != 0:
            raise SnapshotError(
                f"Snapshot measurement failed with exit code {result['exit_code']}; "
                "command output was withheld"
            )
        raw = result["stdout"].strip()
        try:
            value = json.loads(raw.splitlines()[-1]) if raw else {}
        except json.JSONDecodeError:
            value = {"raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}
        if not isinstance(value, dict):
            raise SnapshotError("Snapshot measurement must produce a JSON object")
        return {
            "command_sha256": hashlib.sha256(canonical_json_bytes(command)).hexdigest(),
            "value": value,
            "stdout": _digest_text(result["stdout"]),
            "stderr": _digest_text(result["stderr"]),
        }

    def restore(self, *, phase: str, private_key: Path, public_key: Path) -> dict[str, Any]:
        if phase not in {"before", "after", "maintenance"}:
            raise SnapshotError("Snapshot restore phase is invalid")
        cwd = _direct_directory(
            self.config.cwd, label="Snapshot working directory"
        )
        started = utc_now_iso()
        before = self.measure(phase + "-pre")
        command = self.config.expand(self.config.restore_command, phase)
        cwd = _direct_directory(cwd, label="Snapshot working directory")
        result = _run(command, cwd=cwd, timeout=self.config.timeout_seconds)
        if result["exit_code"] != 0:
            raise SnapshotError(
                f"Snapshot restore failed with exit code {result['exit_code']}; "
                "command output was withheld"
            )
        after = self.measure(phase + "-post")
        expected = _expand_expected(self.config)
        for path, wanted in expected.items():
            actual = _lookup(after["value"], path)
            if actual != wanted:
                raise SnapshotError(f"Snapshot measurement mismatch for {path}: expected {wanted!r}, got {actual!r}")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": self.config.vm_id, "digest": {"sha256": hashlib.sha256(self.config.vm_id.encode()).hexdigest()}}],
            "predicateType": "https://psmatrix.dev/attestation/snapshot-reset/v1",
            "predicate": {
                "schema": 1,
                "adapter_id": self.config.adapter_id,
                "provider": self.config.provider,
                "worker_id": self.config.worker_id,
                "vm_id": self.config.vm_id,
                "snapshot_id": self.config.snapshot_id,
                "phase": phase,
                "started_at": started,
                "finished_at": utc_now_iso(),
                "restore_command_sha256": hashlib.sha256(canonical_json_bytes(command)).hexdigest(),
                "restore_stdout": _digest_text(result["stdout"]),
                "restore_stderr": _digest_text(result["stderr"]),
                "measurement_before": before,
                "measurement_after": after,
                "expected_after": expected,
                "passed": True,
            },
        }
        return create_dsse_envelope(statement, private_key, public_key)


def verify_snapshot_attestation(
    envelope: dict[str, Any],
    public_key: Path,
    *,
    worker_id: str,
    vm_id: str,
    snapshot_id: str,
    phase: str,
) -> dict[str, Any]:
    verified = verify_dsse_envelope(envelope, public_key)
    statement = verified["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/snapshot-reset/v1":
        raise SnapshotError("Unsupported snapshot attestation predicate")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    expected = {
        "worker_id": worker_id,
        "vm_id": vm_id,
        "snapshot_id": snapshot_id,
        "phase": phase,
    }
    if any(predicate.get(key) != value for key, value in expected.items()) or predicate.get("passed") is not True:
        raise SnapshotError("Snapshot attestation does not match the requested reset")
    return {"valid": True, "key_ids": verified["key_ids"], "predicate": predicate}
