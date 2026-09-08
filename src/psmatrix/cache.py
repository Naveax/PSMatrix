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
_CACHE_KEY_HEX = frozenset("0123456789abcdef")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_value(value: Any) -> dict[str, Any]:
    raw = _json_bytes(value)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _digest_bytes(value: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}


def _validate_cache_key(key: str) -> None:
    if len(key) != 64 or any(character not in _CACHE_KEY_HEX for character in key):
        raise ValueError("cache key must be a 64-character lowercase SHA-256 digest")


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _lexical_absolute(path: Path) -> Path:
    """Return an absolute path without dereferencing filesystem indirection."""

    return Path(os.path.abspath(os.fspath(path)))


def _path_boundary_state(path: Path) -> tuple[Path, str | None]:
    """Inspect existing path components before canonicalization.

    ``Path.resolve`` deliberately follows links, which makes it unsuitable for
    deciding whether cache input identity crossed a symlink or Windows reparse
    boundary. Missing suffix components are safe to stop at; an inaccessible
    existing component is represented as unavailable so callers never fall
    back to following it accidentally.
    """

    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError:
            return absolute, "unavailable"
        if _is_link_or_reparse(info):
            return absolute, "indirect"
    return absolute, None


def _direct_directory_stat(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        return None
    return info


def _regular_file_stat(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        return None
    return info


def _directory_evidence(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for name in sorted(dirs):
            item = current_path / name
            relative = item.relative_to(root).as_posix()
            try:
                info = item.lstat()
            except OSError:
                entries.append({"relative_path": relative, "kind": "unavailable"})
                continue
            if _is_link_or_reparse(info):
                entries.append({"relative_path": relative, "kind": "indirect"})
                continue
            if not stat.S_ISDIR(info.st_mode):
                entries.append({"relative_path": relative, "kind": "other"})
                continue
            entries.append({"relative_path": relative, "kind": "directory"})
            safe_dirs.append(name)
        dirs[:] = safe_dirs

        for name in sorted(files):
            item = current_path / name
            relative = item.relative_to(root).as_posix()
            try:
                info = item.lstat()
            except OSError:
                entries.append({"relative_path": relative, "kind": "unavailable"})
                continue
            if _is_link_or_reparse(info):
                entries.append({"relative_path": relative, "kind": "indirect"})
                continue
            if not stat.S_ISREG(info.st_mode):
                entries.append({"relative_path": relative, "kind": "other"})
                continue
            try:
                digest = sha256_file(item)
            except OSError:
                entries.append({"relative_path": relative, "kind": "unavailable-file"})
                continue
            entries.append(
                {
                    "relative_path": relative,
                    "kind": "file",
                    "size": info.st_size,
                    "sha256": digest,
                }
            )
    return entries


def _file_evidence(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    absolute, boundary_state = _path_boundary_state(path)
    if boundary_state == "indirect":
        return {"path": str(absolute), "exists": True, "kind": "indirect"}
    if boundary_state == "unavailable":
        return {"path": str(absolute), "exists": None, "kind": "unavailable"}
    try:
        direct = absolute.resolve()
    except OSError:
        return {"path": str(absolute), "exists": None, "kind": "unavailable"}
    try:
        info = direct.lstat()
    except FileNotFoundError:
        return {"path": str(direct), "exists": False}
    except OSError:
        return {"path": str(direct), "exists": None, "kind": "unavailable"}
    if _is_link_or_reparse(info):
        return {"path": str(absolute), "exists": True, "kind": "indirect"}
    if stat.S_ISREG(info.st_mode):
        try:
            digest = sha256_file(direct)
        except OSError:
            return {"path": str(direct), "exists": True, "kind": "unavailable-file"}
        return {
            "path": str(direct),
            "exists": True,
            "kind": "file",
            "size": info.st_size,
            "sha256": digest,
        }
    if stat.S_ISDIR(info.st_mode):
        return {
            "path": str(direct),
            "exists": True,
            "kind": "directory",
            "entries": _directory_evidence(direct),
        }
    return {"path": str(direct), "exists": True, "kind": "other"}


def _adjacent_input_candidates(source: Path) -> list[Path]:
    return [
        Path(str(source) + ".psmatrix.json"),
        source.with_suffix(source.suffix + ".psmatrix.json"),
        source.with_suffix(".lock.json"),
        source.parent / "psmatrix.lock.json",
    ]


def _adjacent_inputs(source: Path) -> list[dict[str, Any]]:
    seen: set[Path] = set()
    result: list[dict[str, Any]] = []
    for candidate in _adjacent_input_candidates(source):
        identity, boundary_state = _path_boundary_state(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        if boundary_state is None:
            try:
                identity.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                pass
        item = _file_evidence(identity)
        if item is not None:
            result.append(item)
    return result


def execution_context_evidence(source: Path) -> dict[str, Any]:
    """Fingerprint the exact project tree copied into an isolated run workspace.

    ScriptRunner copies ``source.parent`` recursively while excluding a small
    set of generated/vendor directories and all symlinks, Windows reparse
    points, and special files. Cache correctness therefore has to bind the
    result to that same direct regular-file and directory view, not only to the
    entry script. Relative paths are kept because PowerShell behavior can
    depend on file names and ``$PSScriptRoot``; the absolute project location
    is deliberately omitted for portability.
    """

    root = source.resolve().parent
    entries: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in _EXECUTION_CONTEXT_EXCLUDED
            and _direct_directory_stat(current_path / name) is not None
        ]
        relative_dir = current_path.relative_to(root)
        if relative_dir != Path("."):
            entries.append(
                {"relative_path": relative_dir.as_posix(), "kind": "directory"}
            )
        for name in sorted(files):
            item = current_path / name
            info = _regular_file_stat(item)
            if info is None:
                continue
            relative = item.relative_to(root).as_posix()
            try:
                digest = sha256_file(item)
            except OSError:
                entries.append(
                    {"relative_path": relative, "kind": "unavailable-file"}
                )
                continue
            entries.append(
                {
                    "relative_path": relative,
                    "kind": "file",
                    "size": info.st_size,
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

    identity, boundary_state = _path_boundary_state(path)
    if boundary_state is not None or _regular_file_stat(identity) is None:
        return None
    resolved = identity.resolve()
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
    ``None`` so the caller can recompute the complete direct-path adjacent-input
    view instead of mixing evidence from different observation points.
    """

    source = source.resolve()
    root = source.parent
    seen: set[Path] = set()
    result: list[dict[str, Any]] = []
    for candidate in _adjacent_input_candidates(source):
        identity, boundary_state = _path_boundary_state(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        if boundary_state is not None:
            return None
        try:
            info = identity.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
            return None
        item = file_evidence_from_execution_context(identity, root, execution_context)
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

    Only direct regular files represented by the supplied execution context are
    returned. Missing, external, directory, special, symlink, reparse, or
    otherwise indirect inputs are omitted so ``build_cache_material`` retains
    its direct evidence fallback and cannot collapse them onto a target path.
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
        identity, boundary_state = _path_boundary_state(Path(path_value))
        if identity in result or boundary_state is not None:
            continue
        if _regular_file_stat(identity) is None:
            continue
        item = file_evidence_from_execution_context(
            identity,
            context_root,
            execution_context,
        )
        if item is not None:
            result[identity] = item
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
        _lexical_absolute(Path(path)): copy.deepcopy(item)
        for path, item in (precomputed_file_evidence or {}).items()
    }

    def evidence(path_value: str) -> dict[str, Any] | None:
        identity = _lexical_absolute(Path(path_value))
        if identity not in evidence_cache:
            evidence_cache[identity] = _file_evidence(identity)
        return evidence_cache[identity]

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
        self.root.mkdir(parents=True, exist_ok=True)
        self.records = self.root / "targets"
        try:
            self.records.mkdir(exist_ok=False)
        except FileExistsError:
            pass
        if _direct_directory_stat(self.records) is None:
            raise OSError("cache targets path must be a direct directory")
        self._lock = threading.Lock()

    def record_path(self, key: str) -> Path:
        _validate_cache_key(key)
        return self.records / key[:2] / f"{key}.json"

    def _record_files(self) -> list[Path]:
        if _direct_directory_stat(self.records) is None:
            return []
        try:
            shards = list(self.records.iterdir())
        except OSError:
            return []
        result: list[Path] = []
        for shard in shards:
            if _direct_directory_stat(shard) is None:
                continue
            try:
                entries = list(shard.iterdir())
            except OSError:
                continue
            result.extend(
                path
                for path in entries
                if path.suffix == ".json" and _regular_file_stat(path) is not None
            )
        return result

    def load(self, key: str) -> TargetReport | None:
        try:
            path = self.record_path(key)
        except ValueError:
            return None
        if (
            _direct_directory_stat(self.records) is None
            or _direct_directory_stat(path.parent) is None
            or _regular_file_stat(path) is None
        ):
            return None
        try:
            payload = read_json(path)
            if (
                payload.get("schema") != _CACHE_SCHEMA
                or payload.get("key") != key
                or payload.get("material_digest") != key
            ):
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
        report_value = report.to_dict()
        resolved_material_digest = (
            material_digest
            if material_digest is not None
            else hashlib.sha256(_json_bytes(_portable(material))).hexdigest()
        )
        if key != resolved_material_digest:
            return False
        payload = {
            "schema": _CACHE_SCHEMA,
            "key": key,
            "created_at": utc_now_iso(),
            "material_digest": resolved_material_digest,
            "report_sha256": hashlib.sha256(_json_bytes(report_value)).hexdigest(),
            "report": report_value,
        }
        with self._lock:
            if _direct_directory_stat(self.records) is None:
                return False
            try:
                path.parent.mkdir(exist_ok=False)
            except FileExistsError:
                pass
            except OSError:
                return False
            if _direct_directory_stat(path.parent) is None:
                return False
            atomic_write_json(path, payload)
        return True

    def clear(self) -> dict[str, int]:
        before = self.stats()
        if _direct_directory_stat(self.records) is None:
            raise OSError("refusing to clear an indirect cache targets path")
        try:
            shutil.rmtree(self.records)
        except FileNotFoundError:
            pass
        self.records.mkdir(parents=True, exist_ok=True)
        if _direct_directory_stat(self.records) is None:
            raise OSError("cache targets path could not be recreated safely")
        return before

    def prune(self, *, max_age_days: float | None = None, max_records: int | None = None) -> dict[str, int]:
        files = self._record_files()
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
                    info = _regular_file_stat(path)
                    if info is None:
                        files.remove(path)
                        continue
                    created = datetime.fromtimestamp(info.st_mtime, UTC)
                if created < cutoff:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        files.remove(path)
                        continue
                    except OSError:
                        continue
                    files.remove(path)
                    removed += 1
        if max_records is not None:
            ranked = []
            for path in files:
                info = _regular_file_stat(path)
                if info is not None:
                    ranked.append((path, info.st_mtime))
            ranked.sort(key=lambda item: item[1], reverse=True)
            for path, _mtime in ranked[max_records:]:
                try:
                    path.unlink()
                except FileNotFoundError:
                    continue
                except OSError:
                    continue
                removed += 1
        if _direct_directory_stat(self.records) is None:
            directories = []
        else:
            try:
                directories = list(self.records.iterdir())
            except OSError:
                directories = []
        for directory in directories:
            if _direct_directory_stat(directory) is not None:
                try:
                    directory.rmdir()
                except OSError:
                    pass
        return {"removed": removed, **self.stats()}

    def stats(self) -> dict[str, int]:
        records = 0
        total_bytes = 0
        for path in self._record_files():
            info = _regular_file_stat(path)
            if info is None:
                continue
            records += 1
            total_bytes += info.st_size
        return {"records": records, "bytes": total_bytes}
