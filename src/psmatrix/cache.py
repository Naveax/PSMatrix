from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import shutil
import copy
from datetime import UTC, datetime, timedelta
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import RuntimeSpec, TargetReport, target_report_from_dict
from .util import atomic_write_json, read_json, sha256_file, utc_now_iso

_CACHE_SCHEMA = 2
_EXECUTION_CONTEXT_EXCLUDED = {".git", ".psmatrix", "node_modules", "target", "__pycache__"}


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_value(value: Any) -> dict[str, Any]:
    raw = _json_bytes(value)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _file_evidence(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = path.resolve()
    if not resolved.exists():
        return {"path": str(resolved), "exists": False}
    if resolved.is_symlink():
        return {"path": str(resolved), "exists": True, "symlink": True, "target": os.readlink(resolved)}
    if resolved.is_file():
        return {
            "path": str(resolved),
            "exists": True,
            "kind": "file",
            "size": resolved.stat().st_size,
            "sha256": sha256_file(resolved),
        }
    if resolved.is_dir():
        entries: list[dict[str, Any]] = []
        for item in sorted(resolved.rglob("*")):
            relative = item.relative_to(resolved).as_posix()
            if item.is_symlink():
                entries.append({"relative_path": relative, "kind": "symlink", "target": os.readlink(item)})
            elif item.is_file():
                entries.append({"relative_path": relative, "kind": "file", "size": item.stat().st_size, "sha256": sha256_file(item)})
            elif item.is_dir():
                entries.append({"relative_path": relative, "kind": "directory"})
        return {"path": str(resolved), "exists": True, "kind": "directory", "entries": entries}
    return {"path": str(resolved), "exists": True, "kind": "other"}


def _adjacent_inputs(source: Path) -> list[dict[str, Any]]:
    candidates = [
        Path(str(source) + ".psmatrix.json"),
        source.with_suffix(source.suffix + ".psmatrix.json"),
        source.with_suffix(".lock.json"),
        source.parent / "psmatrix.lock.json",
    ]
    seen: set[Path] = set()
    result = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.exists():
            result.append(_file_evidence(resolved))
    return [item for item in result if item is not None]


def execution_context_evidence(source: Path) -> dict[str, Any]:
    """Fingerprint the exact project tree copied into an isolated run workspace.

    ScriptRunner copies ``source.parent`` recursively while excluding a small
    set of generated/vendor directories and all symlinks/special files. Cache
    correctness therefore has to bind the result to that same regular-file
    and directory view, not only to the entry script. Relative paths are kept
    because PowerShell behavior can depend on file names and ``$PSScriptRoot``;
    the absolute project location is deliberately omitted for portability.
    """

    root = source.resolve().parent
    entries: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in _EXECUTION_CONTEXT_EXCLUDED
            and not (current_path / name).is_symlink()
        ]
        relative_dir = current_path.relative_to(root)
        if relative_dir != Path("."):
            entries.append(
                {"relative_path": relative_dir.as_posix(), "kind": "directory"}
            )
        for name in sorted(files):
            item = current_path / name
            try:
                mode = item.lstat().st_mode
            except OSError:
                continue
            if not stat.S_ISREG(mode):
                continue
            relative = item.relative_to(root).as_posix()
            try:
                size = item.stat().st_size
                digest = sha256_file(item)
            except OSError:
                continue
            entries.append(
                {
                    "relative_path": relative,
                    "kind": "file",
                    "size": size,
                    "sha256": digest,
                }
            )
    return {"kind": "execution-context", "entries": entries}


def engine_fingerprint(root: Path) -> dict[str, Any]:
    root = root.resolve()
    files = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix in {".py", ".ps1"}:
            files.append({"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size})
    digest = hashlib.sha256(_json_bytes(files)).hexdigest()
    return {"digest": digest, "files": files}


def installed_modules_fingerprint(items: list[dict[str, Any]]) -> dict[str, Any]:
    modules = []
    for item in items:
        payload = {
            "name": item.get("name"),
            "version": item.get("version"),
            "package_sha256": item.get("sha256"),
            "verified": item.get("verified"),
            "healthy": item.get("healthy"),
        }
        path_value = item.get("path")
        if path_value:
            evidence = _file_evidence(Path(str(path_value)))
            payload["content"] = evidence
        modules.append(payload)
    modules.sort(key=lambda value: (str(value.get("name")), str(value.get("version"))))
    return {"digest": hashlib.sha256(_json_bytes(modules)).hexdigest(), "modules": modules}


def build_cache_material(
    source: Path,
    spec: RuntimeSpec,
    options: Any,
    *,
    tool_version: str,
    runtime_fingerprint: dict[str, Any] | None = None,
    execution_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = source.resolve()
    raw = asdict(options)
    # Values affect the key but never appear in plaintext in cache metadata.
    raw["stdin_data"] = _digest_value(raw.get("stdin_data")) if raw.get("stdin_data") is not None else None
    raw["parameters"] = [
        {"name": name, "value": _digest_value(value)} for name, value in raw.get("parameters", [])
    ]
    raw["environment"] = [
        {"name": name, "value": _digest_value(value)} for name, value in raw.get("environment", [])
    ]

    def token(path_value: str) -> dict[str, Any]:
        evidence = _file_evidence(Path(path_value)) or {"exists": False}
        evidence.pop("path", None)
        return evidence

    raw["setup_scripts"] = [token(value) for value in raw.get("setup_scripts", [])]
    raw["teardown_scripts"] = [token(value) for value in raw.get("teardown_scripts", [])]
    raw["fixtures"] = [
        {"source": token(source_value), "destination": destination}
        for source_value, destination in raw.get("fixtures", [])
    ]
    raw["dependency_lockfile"] = (
        token(raw["dependency_lockfile"]) if raw.get("dependency_lockfile") else None
    )
    raw["stdin_source"] = "provided" if raw.get("stdin_source") else None

    files: list[dict[str, Any]] = []
    original = asdict(options)
    for value in original.get("setup_scripts", []) + original.get("teardown_scripts", []):
        item = _file_evidence(Path(value))
        if item:
            files.append(item)
    for source_value, _destination in original.get("fixtures", []):
        item = _file_evidence(Path(source_value))
        if item:
            files.append(item)
    lockfile = original.get("dependency_lockfile")
    if lockfile:
        item = _file_evidence(Path(lockfile))
        if item:
            files.append(item)

    material = {
        "schema": _CACHE_SCHEMA,
        "tool_version": tool_version,
        "source": _file_evidence(source),
        "execution_context": execution_context or execution_context_evidence(source),
        "adjacent_inputs": _adjacent_inputs(source),
        "referenced_inputs": files,
        "runtime": {
            "runtime_id": spec.runtime_id,
            "version": spec.version,
            "os": spec.os,
            "arch": spec.arch,
            "libc": spec.libc,
            "fingerprint": runtime_fingerprint or {},
        },
        "options": raw,
    }
    return material


def _portable(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _portable(item)
            for key, item in sorted(value.items())
            if key not in {"path", "stdin_source"}
        }
    if isinstance(value, (list, tuple)):
        return [_portable(item) for item in value]
    return value


def cache_key(material: dict[str, Any]) -> str:
    return hashlib.sha256(_json_bytes(_portable(material))).hexdigest()


def shard_key(material: dict[str, Any]) -> str:
    value = copy.deepcopy(material)
    runtime = value.get("runtime")
    if isinstance(runtime, dict):
        runtime.pop("fingerprint", None)
    value.pop("tool_modules", None)
    value.pop("engine", None)
    return hashlib.sha256(_json_bytes(_portable(value))).hexdigest()


class ResultCache:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.records = self.root / "targets"
        self.records.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record_path(self, key: str) -> Path:
        return self.records / key[:2] / f"{key}.json"

    def load(self, key: str) -> TargetReport | None:
        path = self.record_path(key)
        if not path.is_file():
            return None
        try:
            payload = read_json(path)
            if payload.get("schema") != _CACHE_SCHEMA or payload.get("key") != key:
                return None
            report_value = payload["report"]
            expected = payload.get("report_sha256")
            actual = hashlib.sha256(_json_bytes(report_value)).hexdigest()
            if expected != actual:
                return None
            report = target_report_from_dict(report_value)
            if report.status != "PASS":
                return None
            report.cache = {
                "status": "hit",
                "key": key,
                "created_at": payload.get("created_at"),
            }
            return report
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def store(self, key: str, report: TargetReport, material: dict[str, Any]) -> bool:
        if report.status != "PASS":
            return False
        path = self.record_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        report_value = report.to_dict()
        payload = {
            "schema": _CACHE_SCHEMA,
            "key": key,
            "created_at": utc_now_iso(),
            "material_digest": hashlib.sha256(_json_bytes(_portable(material))).hexdigest(),
            "report_sha256": hashlib.sha256(_json_bytes(report_value)).hexdigest(),
            "report": report_value,
        }
        with self._lock:
            atomic_write_json(path, payload)
        return True

    def clear(self) -> dict[str, int]:
        before = self.stats()
        if self.records.exists():
            shutil.rmtree(self.records)
        self.records.mkdir(parents=True, exist_ok=True)
        return before

    def prune(self, *, max_age_days: float | None = None, max_records: int | None = None) -> dict[str, int]:
        files = [path for path in self.records.glob("*/*.json") if path.is_file()]
        removed = 0
        now = datetime.now(UTC)
        if max_age_days is not None:
            cutoff = now - timedelta(days=max_age_days)
            for path in list(files):
                try:
                    payload = read_json(path)
                    created = datetime.fromisoformat(str(payload.get("created_at")))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=UTC)
                except (OSError, ValueError, TypeError):
                    created = datetime.fromtimestamp(path.stat().st_mtime, UTC)
                if created < cutoff:
                    path.unlink(missing_ok=True)
                    files.remove(path)
                    removed += 1
        if max_records is not None and len(files) > max_records:
            files.sort(key=lambda item: item.stat().st_mtime, reverse=True)
            for path in files[max_records:]:
                path.unlink(missing_ok=True)
                removed += 1
        for directory in self.records.iterdir() if self.records.exists() else []:
            if directory.is_dir():
                try:
                    directory.rmdir()
                except OSError:
                    pass
        return {"removed": removed, **self.stats()}

    def stats(self) -> dict[str, int]:
        files = list(self.records.glob("*/*.json"))
        return {"records": len(files), "bytes": sum(path.stat().st_size for path in files if path.is_file())}
