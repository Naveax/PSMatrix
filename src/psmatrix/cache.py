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


def _digest_bytes(value: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}


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


def _adjacent_input_candidates(source: Path) -> list[Path]:
    return [
        Path(str(source) + ".psmatrix.json"),
        source.with_suffix(source.suffix + ".psmatrix.json"),
        source.with_suffix(".lock.json"),
        source.parent / "psmatrix.lock.json",
    ]


def _adjacent_inputs(source: Path) -> list[dict[str, Any]]:
    seen: set[Path] = set()
    result = []
    for candidate in _adjacent_input_candidates(source):
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


def file_evidence_from_execution_context(
    path: Path,
    context_root: Path,
    execution_context: dict[str, Any],
) -> dict[str, Any] | None:
    """Recover regular-file evidence from a compatible execution context.

    This helper validates structure and relative-path membership only. Freshness
    is the caller's responsibility; scheduler fast paths use it only with a
    context scanned in the current source iteration.
    """

    resolved = path.resolve()
    root = context_root.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        return None
    entries = execution_context.get("entries")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("relative_path") != relative or entry.get("kind") != "file":
            continue
        size = entry.get("size")
        digest = entry.get("sha256")
        if not isinstance(size, int) or not isinstance(digest, str) or not digest:
            return None
        return {
            "path": str(resolved),
            "exists": True,
            "kind": "file",
            "size": size,
            "sha256": digest,
        }
    return None


def source_evidence_from_execution_context(
    source: Path,
    execution_context: dict[str, Any],
) -> dict[str, Any] | None:
    """Recover entry-script evidence from a freshly scanned execution context."""

    resolved = source.resolve()
    return file_evidence_from_execution_context(
        resolved,
        resolved.parent,
        execution_context,
    )


def adjacent_inputs_from_execution_context(
    source: Path,
    execution_context: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Recover all existing adjacent-input evidence from a fresh context.

    The fast path is all-or-nothing. If any existing candidate cannot be
    represented exactly by regular-file execution-context evidence, return
    ``None`` so the caller can recompute the complete legacy adjacent-input
    view instead of mixing evidence from different observation points.
    """

    source = source.resolve()
    root = source.parent
    seen: set[Path] = set()
    result: list[dict[str, Any]] = []
    for candidate in _adjacent_input_candidates(source):
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.exists():
            continue
        item = file_evidence_from_execution_context(resolved, root, execution_context)
        if item is None:
            return None
        result.append(item)
    return result


def referenced_input_evidence_from_execution_context(
    options: Any,
    context_root: Path,
    execution_context: dict[str, Any],
) -> dict[Path, dict[str, Any]]:
    """Collect reusable regular-file evidence for explicit run inputs.

    Only inputs represented by the supplied execution context are returned.
    Missing, external, directory, special, or malformed inputs are omitted so
    `build_cache_material` retains its normal per-path direct evidence fallback.
    """

    path_values = list(getattr(options, "setup_scripts", ()))
    path_values.extend(getattr(options, "teardown_scripts", ()))
    path_values.extend(
        source_value
        for source_value, _destination in getattr(options, "fixtures", ())
    )
    lockfile = getattr(options, "dependency_lockfile", None)
    if lockfile:
        path_values.append(lockfile)

    result: dict[Path, dict[str, Any]] = {}
    for path_value in path_values:
        resolved = Path(path_value).resolve()
        if resolved in result:
            continue
        item = file_evidence_from_execution_context(
            resolved,
            context_root,
            execution_context,
        )
        if item is not None:
            result[resolved] = item
    return result


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
    source_evidence: dict[str, Any] | None = None,
    adjacent_inputs_evidence: list[dict[str, Any]] | None = None,
    precomputed_file_evidence: dict[Path, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    source = source.resolve()
    raw = asdict(options)
    setup_scripts = raw.get("setup_scripts", ())
    teardown_scripts = raw.get("teardown_scripts", ())
    fixtures = raw.get("fixtures", ())
    lockfile = raw.get("dependency_lockfile")
    evidence_cache: dict[Path, dict[str, Any] | None] = {
        Path(path).resolve(): copy.deepcopy(item)
        for path, item in (precomputed_file_evidence or {}).items()
    }

    def evidence(path_value: str) -> dict[str, Any] | None:
        resolved = Path(path_value).resolve()
        if resolved not in evidence_cache:
            evidence_cache[resolved] = _file_evidence(resolved)
        return evidence_cache[resolved]

    # Values affect the key but never appear in plaintext in cache metadata.
    raw["stdin_data"] = _digest_bytes(raw["stdin_data"]) if raw.get("stdin_data") is not None else None
    raw["parameters"] = [
        {"name": name, "value": _digest_value(value)} for name, value in raw.get("parameters", [])
    ]
    raw["environment"] = [
        {"name": name, "value": _digest_value(value)} for name, value in raw.get("environment", [])
    ]

    def token(path_value: str) -> dict[str, Any]:
        item = evidence(path_value)
        value = copy.deepcopy(item) if item is not None else {"exists": False}
        value.pop("path", None)
        return value

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
    for value in setup_scripts + teardown_scripts:
        item = evidence(value)
        if item:
            files.append(copy.deepcopy(item))
    for source_value, _destination in fixtures:
        item = evidence(source_value)
        if item:
            files.append(copy.deepcopy(item))
    if lockfile:
        item = evidence(lockfile)
        if item:
            files.append(copy.deepcopy(item))

    material = {
        "schema": _CACHE_SCHEMA,
        "tool_version": tool_version,
        "source": copy.deepcopy(source_evidence) if source_evidence is not None else _file_evidence(source),
        "execution_context": (
            execution_context
            if execution_context is not None
            else execution_context_evidence(source)
        ),
        "adjacent_inputs": (
            copy.deepcopy(adjacent_inputs_evidence)
            if adjacent_inputs_evidence is not None
            else _adjacent_inputs(source)
        ),
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
    runtime = material.get("runtime")
    projected_runtime = (
        {key: item for key, item in runtime.items() if key != "fingerprint"}
        if isinstance(runtime, dict)
        else runtime
    )
    value = {
        key: projected_runtime if key == "runtime" else item
        for key, item in material.items()
        if key not in {"execution_context", "tool_modules", "engine"}
    }
    return hashlib.sha256(_json_bytes(_portable(value))).hexdigest()


def cache_and_shard_keys(material: dict[str, Any]) -> tuple[str, str]:
    portable = _portable(material)
    cache_digest = hashlib.sha256(_json_bytes(portable)).hexdigest()
    runtime = portable.get("runtime")
    projected_runtime = (
        {key: item for key, item in runtime.items() if key != "fingerprint"}
        if isinstance(runtime, dict)
        else runtime
    )
    shard_material = {
        key: projected_runtime if key == "runtime" else item
        for key, item in portable.items()
        if key not in {"execution_context", "tool_modules", "engine"}
    }
    shard_digest = hashlib.sha256(_json_bytes(shard_material)).hexdigest()
    return cache_digest, shard_digest


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

    def store(
        self,
        key: str,
        report: TargetReport,
        material: dict[str, Any],
        *,
        material_digest: str | None = None,
    ) -> bool:
        if report.status != "PASS":
            return False
        path = self.record_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        report_value = report.to_dict()
        resolved_material_digest = (
            material_digest
            if material_digest is not None
            else hashlib.sha256(_json_bytes(_portable(material))).hexdigest()
        )
        payload = {
            "schema": _CACHE_SCHEMA,
            "key": key,
            "created_at": utc_now_iso(),
            "material_digest": resolved_material_digest,
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
