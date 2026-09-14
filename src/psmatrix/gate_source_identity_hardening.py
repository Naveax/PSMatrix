from __future__ import annotations

import hashlib
import hmac
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_INSTALLED = False
_ORIGINAL_CREATE: Any = None
_ORIGINAL_VERIFY: Any = None
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ProjectFileSnapshot:
    path: Path
    relative: str
    sha256: str
    size: int


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _after_gate_source_open(path: Path) -> None:
    """Deterministic replacement-race hook used by regression tests."""


def _validate_regular(gate: Any, info: os.stat_result, path: Path) -> None:
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise gate.GateError(f"Delivery gate source is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise gate.GateError(f"Delivery gate source must have exactly one hard link: {path}")


def _read_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def _snapshot_posix(gate: Any, root: Path, target: Path, relative: str) -> ProjectFileSnapshot:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
    ):
        raise gate.GateError("Descriptor-relative delivery gate reads are unavailable")

    directory_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    root_fd = -1
    file_fd = -1
    opened_dirs: list[tuple[int, str, int, tuple[int, int], Path]] = []
    try:
        root_fd = os.open(root, directory_flags)
        root_opened = os.fstat(root_fd)
        root_visible = root.lstat()
        if (
            _is_reparse(root_opened)
            or _is_reparse(root_visible)
            or not stat.S_ISDIR(root_opened.st_mode)
            or not stat.S_ISDIR(root_visible.st_mode)
            or _identity(root_opened) != _identity(root_visible)
        ):
            raise gate.GateError("Delivery gate project root identity is unsafe")
        root_identity = _identity(root_opened)

        current_fd = root_fd
        current_path = root
        parts = Path(relative).parts
        if not parts:
            raise gate.GateError("Delivery gate source path is empty")

        for name in parts[:-1]:
            child_path = current_path / name
            before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if _is_reparse(before) or not stat.S_ISDIR(before.st_mode):
                raise gate.GateError(f"Delivery gate source parent is indirect: {child_path}")
            child_fd = os.open(name, directory_flags, dir_fd=current_fd)
            opened = os.fstat(child_fd)
            visible = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            expected = _identity(opened)
            if (
                _is_reparse(opened)
                or not stat.S_ISDIR(opened.st_mode)
                or _identity(before) != expected
                or _identity(visible) != expected
            ):
                os.close(child_fd)
                raise gate.GateError(f"Delivery gate source parent identity changed: {child_path}")
            opened_dirs.append((current_fd, name, child_fd, expected, child_path))
            current_fd = child_fd
            current_path = child_path

        name = parts[-1]
        before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        _validate_regular(gate, before, target)
        file_fd = os.open(name, file_flags, dir_fd=current_fd)
        opened = os.fstat(file_fd)
        visible = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        _validate_regular(gate, opened, target)
        _validate_regular(gate, visible, target)
        expected_file = _identity(opened)
        if _identity(before) != expected_file or _identity(visible) != expected_file:
            raise gate.GateError(f"Delivery gate source identity changed while opening: {target}")

        _after_gate_source_open(target)
        digest, total = _read_fd(file_fd)

        final = os.fstat(file_fd)
        visible_final = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        _validate_regular(gate, final, target)
        _validate_regular(gate, visible_final, target)
        if _identity(final) != expected_file or _identity(visible_final) != expected_file:
            raise gate.GateError(f"Delivery gate source identity changed during read: {target}")
        if int(final.st_size) != total:
            raise gate.GateError(f"Delivery gate source size changed during read: {target}")

        for parent_fd, child_name, child_fd, expected, child_path in reversed(opened_dirs):
            pinned = os.fstat(child_fd)
            visible_parent = os.stat(child_name, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(pinned) != expected or _identity(visible_parent) != expected:
                raise gate.GateError(
                    f"Delivery gate source parent identity changed during read: {child_path}"
                )

        root_final = os.fstat(root_fd)
        root_visible_final = root.lstat()
        if _identity(root_final) != root_identity or _identity(root_visible_final) != root_identity:
            raise gate.GateError("Delivery gate project root identity changed during read")
        return ProjectFileSnapshot(target, relative, digest, total)
    except OSError as exc:
        raise gate.GateError(f"Unable to snapshot delivery gate source {target}: {exc}") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for _, _, child_fd, _, _ in reversed(opened_dirs):
            try:
                os.close(child_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass


def _snapshot_windows(gate: Any, root: Path, target: Path, relative: str) -> ProjectFileSnapshot:
    from . import http_artifact_read_hardening as direct
    from . import remote_zip_hardening as zip_hardening

    worker = SimpleNamespace(WorkerError=gate.GateError)
    session_like = SimpleNamespace(SessionError=gate.GateError)
    handles: list[Any] = []
    pinned: list[tuple[Path, tuple[int, int]]] = []
    try:
        for component in zip_hardening._windows_chain(target.parent):
            handle, identity = zip_hardening._open_windows_directory(worker, component)
            handles.append(handle)
            pinned.append((component, identity))
        with direct._open_direct_source(session_like, target) as source:
            opened = os.fstat(source.fileno())
            _validate_regular(gate, opened, target)
            expected = _identity(opened)
            _after_gate_source_open(target)
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
            final = os.fstat(source.fileno())
            _validate_regular(gate, final, target)
            if _identity(final) != expected or int(final.st_size) != total:
                raise gate.GateError(f"Delivery gate source identity changed during read: {target}")
        for component, expected_dir in pinned:
            check, actual = zip_hardening._open_windows_directory(worker, component)
            try:
                if actual != expected_dir:
                    raise gate.GateError(
                        f"Delivery gate source parent identity changed during read: {component}"
                    )
            finally:
                zip_hardening._close_windows_handle(check)
        return ProjectFileSnapshot(target, relative, digest.hexdigest(), total)
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def snapshot_project_file(root: Path, value: str | Path) -> ProjectFileSnapshot:
    from . import gate

    root = root.resolve()
    target = gate.resolve_project_file(root, str(value))
    relative = target.relative_to(root).as_posix()
    if os.name == "nt":
        return _snapshot_windows(gate, root, target, relative)
    return _snapshot_posix(gate, root, target, relative)


def _hardened_create_gate_receipt(
    report: dict[str, Any],
    root: Path,
    home: Path,
    *,
    transaction_id: str | None = None,
    allowed_statuses: tuple[str, ...] = ("PASS",),
) -> dict[str, Any]:
    from . import gate

    root = root.resolve()
    status = str(report.get("status"))
    if status not in allowed_statuses:
        raise gate.GateError(f"Delivery gate requires {allowed_statuses}; got {status}")
    sources: dict[str, dict[str, Any]] = {}
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        source_value = str(target.get("source") or "")
        if not source_value:
            continue
        source = snapshot_project_file(root, source_value)
        sources[source.relative] = {
            "path": source.relative,
            "sha256": source.sha256,
            "size": source.size,
        }
    if not sources:
        raise gate.GateError("Delivery gate report contains no project sources")
    unsigned = {
        "schema": gate._GATE_SCHEMA,
        "kind": "psmatrix.delivery-gate",
        "created_at": gate.utc_now_iso(),
        "tool_version": report.get("tool_version"),
        "report_status": status,
        "report_sha256": hashlib.sha256(gate._canonical_bytes(report)).hexdigest(),
        "transaction_id": transaction_id,
        "root": str(root),
        "sources": [sources[key] for key in sorted(sources)],
        "runtime_ids": sorted({
            str(target.get("runtime_id"))
            for target in report.get("targets", [])
            if isinstance(target, dict) and target.get("runtime_id")
        }),
    }
    key = gate._load_key(home, create=True)
    signature = hmac.new(key, gate._canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": {"algorithm": "HMAC-SHA256", "value": signature}}


def _hardened_verify_gate_receipt(
    receipt: dict[str, Any],
    root: Path,
    home: Path,
) -> dict[str, Any]:
    from . import gate

    root = root.resolve()
    if receipt.get("schema") != gate._GATE_SCHEMA or receipt.get("kind") != "psmatrix.delivery-gate":
        raise gate.GateError("Unsupported delivery gate receipt")
    if str(receipt.get("root") or "") != str(root):
        raise gate.GateError("Delivery gate receipt belongs to a different project root")
    signature = receipt.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
        raise gate.GateError("Delivery gate signature is missing or unsupported")
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    key = gate._load_key(home, create=False)
    expected = hmac.new(key, gate._canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    actual = str(signature.get("value") or "")
    if not hmac.compare_digest(expected, actual):
        raise gate.GateError("Delivery gate signature verification failed")

    stale: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    sources = receipt.get("sources")
    if not isinstance(sources, list) or not sources:
        raise gate.GateError("Delivery gate receipt contains no sources")
    for item in sources:
        if not isinstance(item, dict):
            raise gate.GateError("Delivery gate source entries must be objects")
        relative = str(item.get("path") or "")
        expected_hash = str(item.get("sha256") or "").lower()
        try:
            expected_size = int(item.get("size"))
        except (TypeError, ValueError):
            stale.append({"path": relative, "reason": "size is invalid"})
            continue
        if expected_size < 0:
            stale.append({"path": relative, "reason": "size is invalid"})
            continue
        try:
            source = snapshot_project_file(root, relative)
        except (gate.PSMatrixError, OSError) as exc:
            stale.append({"path": relative, "reason": str(exc)})
            continue
        if not hmac.compare_digest(expected_hash, source.sha256):
            stale.append({
                "path": relative,
                "reason": "sha256 changed",
                "expected": expected_hash,
                "actual": source.sha256,
            })
        elif source.size != expected_size:
            stale.append({
                "path": relative,
                "reason": "size changed",
                "expected": expected_size,
                "actual": source.size,
            })
        else:
            verified.append({"path": relative, "sha256": source.sha256, "size": source.size})
    return {
        "valid": not stale,
        "signature_valid": True,
        "stale": stale,
        "verified_sources": verified,
        "report_status": receipt.get("report_status"),
        "report_sha256": receipt.get("report_sha256"),
        "transaction_id": receipt.get("transaction_id"),
    }


def install() -> None:
    global _INSTALLED, _ORIGINAL_CREATE, _ORIGINAL_VERIFY
    if _INSTALLED:
        return

    from . import gate

    if getattr(gate, "_source_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_CREATE = gate.create_gate_receipt
    _ORIGINAL_VERIFY = gate.verify_gate_receipt
    gate.create_gate_receipt = _hardened_create_gate_receipt
    gate.verify_gate_receipt = _hardened_verify_gate_receipt
    gate._source_identity_hardened = True
    _INSTALLED = True
