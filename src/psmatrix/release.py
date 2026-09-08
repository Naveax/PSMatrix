from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import PSMatrixError
from .signing import create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_bytes, atomic_write_json, sha256_file, utc_now_iso


class ReleaseError(PSMatrixError):
    """Raised when a release cannot be reproduced or verified."""


def _build_time() -> str:
    from datetime import UTC, datetime

    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ReleaseError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise ReleaseError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(epoch, UTC).isoformat()


_EXCLUDED_PARTS = {".git", ".psmatrix", "__pycache__", ".pytest_cache", "dist", "build"}
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class _SourceSnapshot:
    path: Path
    relative: Path
    data: bytes
    mode: int


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
            raise ReleaseError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise ReleaseError(
                f"{label} cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReleaseError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise ReleaseError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise ReleaseError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(f"{label} must be a direct directory: {candidate}")
    return candidate


def _read_direct_file(path: Path, *, label: str) -> tuple[Path, bytes, os.stat_result]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise ReleaseError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise ReleaseError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise ReleaseError(f"{label} must be a direct regular file: {candidate}")

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
                raise ReleaseError(f"{label} changed while opening: {candidate}")
            data = handle.read()
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
                raise ReleaseError(f"{label} changed while reading: {candidate}")
    except ReleaseError:
        raise
    except OSError as exc:
        raise ReleaseError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise ReleaseError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISREG(final.st_mode)
        or not _same_file(final, opened_after)
    ):
        raise ReleaseError(f"{label} changed after read: {candidate}")
    return candidate, data, opened_after


def _direct_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    parent = _direct_directory(candidate.parent, label=f"{label} parent", create=True)
    candidate = _reject_indirect_components(parent / candidate.name, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise ReleaseError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _safe_release_name(name: str) -> str:
    value = str(name)
    if (
        not value
        or value in {".", ".."}
        or Path(value).name != value
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ReleaseError("Release source archive name is unsafe")
    return value


def _excluded(relative: Path) -> bool:
    return any(
        part in _EXCLUDED_PARTS or part.endswith(".egg-info")
        for part in relative.parts
    )


def _release_paths(root: Path) -> tuple[Path, list[Path]]:
    root = _direct_directory(root, label="Release source root")
    result: list[Path] = []
    try:
        walker = os.walk(root, topdown=True, followlinks=False)
        for current_raw, dirnames, filenames in walker:
            current = _direct_directory(Path(current_raw), label="Release source directory")
            current_relative = current.relative_to(root)
            kept_dirs: list[str] = []
            for name in sorted(dirnames):
                relative = current_relative / name
                if _excluded(relative):
                    continue
                candidate = current / name
                try:
                    info = candidate.lstat()
                except OSError as exc:
                    raise ReleaseError(
                        f"Unable to inspect release source directory: {relative}"
                    ) from exc
                if _is_link_or_reparse(info):
                    raise ReleaseError(
                        f"Release source contains a symlink or reparse point: {relative}"
                    )
                if stat.S_ISDIR(info.st_mode):
                    kept_dirs.append(name)
            dirnames[:] = kept_dirs

            for name in sorted(filenames):
                relative = current_relative / name
                if _excluded(relative):
                    continue
                candidate = current / name
                try:
                    info = candidate.lstat()
                except OSError as exc:
                    raise ReleaseError(
                        f"Unable to inspect release source file: {relative}"
                    ) from exc
                if _is_link_or_reparse(info):
                    raise ReleaseError(
                        f"Release source contains a symlink or reparse point: {relative}"
                    )
                if stat.S_ISREG(info.st_mode):
                    result.append(candidate)
    except ReleaseError:
        raise
    except OSError as exc:
        raise ReleaseError(f"Unable to traverse release source root: {root}") from exc
    result.sort(key=lambda item: item.relative_to(root).as_posix())
    return root, result


def release_files(root: Path) -> list[Path]:
    _, files = _release_paths(root)
    return files


def _mode(info: os.stat_result) -> int:
    executable = bool(info.st_mode & stat.S_IXUSR)
    return 0o100755 if executable else 0o100644


def _source_snapshot(root: Path) -> tuple[Path, list[_SourceSnapshot]]:
    root, paths = _release_paths(root)
    snapshots: list[_SourceSnapshot] = []
    for path in paths:
        direct, data, info = _read_direct_file(
            path, label=f"Release source file {path.relative_to(root).as_posix()}"
        )
        snapshots.append(
            _SourceSnapshot(
                path=direct,
                relative=direct.relative_to(root),
                data=data,
                mode=_mode(info),
            )
        )
    return root, snapshots


def _write_verified_bytes(path: Path, data: bytes, *, label: str) -> tuple[Path, bytes]:
    path = _direct_output_file(path, label=label)
    atomic_write_bytes(path, data)
    persisted_path, persisted, _ = _read_direct_file(path, label=label)
    if persisted != data:
        raise ReleaseError(f"{label} changed after write")
    return persisted_path, persisted


def build_reproducible_source(root: Path, output_dir: Path, *, name: str) -> dict[str, Any]:
    name = _safe_release_name(name)
    _, files = _source_snapshot(root)
    if not files:
        raise ReleaseError("Release source tree is empty")
    output_dir = _direct_directory(output_dir, label="Release output directory", create=True)
    zip_path = output_dir / f"{name}-source.zip"
    tar_path = output_dir / f"{name}-source.tar.gz"

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(
        zip_buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for item in files:
            relative = f"{name}/{item.relative.as_posix()}"
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = item.mode << 16
            archive.writestr(info, item.data)
    zip_path, zip_bytes = _write_verified_bytes(
        zip_path, zip_buffer.getvalue(), label="Release source ZIP"
    )

    tar_raw = io.BytesIO()
    with tarfile.open(fileobj=tar_raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for item in files:
            relative = f"{name}/{item.relative.as_posix()}"
            info = tarfile.TarInfo(relative)
            info.size = len(item.data)
            info.mode = 0o755 if item.mode == 0o100755 else 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(item.data))
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(
        fileobj=gz_buffer, mode="wb", filename="", mtime=0, compresslevel=9
    ) as gz:
        gz.write(tar_raw.getvalue())
    tar_path, tar_bytes = _write_verified_bytes(
        tar_path, gz_buffer.getvalue(), label="Release source TAR.GZ"
    )
    return {
        "zip": {
            "path": str(zip_path),
            "sha256": hashlib.sha256(zip_bytes).hexdigest(),
            "size": len(zip_bytes),
        },
        "tar_gz": {
            "path": str(tar_path),
            "sha256": hashlib.sha256(tar_bytes).hexdigest(),
            "size": len(tar_bytes),
        },
        "source_files": len(files),
    }


def create_release_manifest(
    artifacts: Iterable[Path],
    output: Path,
    *,
    version: str,
    signing_private_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    unique = {_lexical_absolute(path) for path in artifacts}
    artifacts_ordered = sorted(unique, key=lambda path: path.name)
    if not artifacts_ordered:
        raise ReleaseError("Release artifacts are missing")

    snapshots: list[tuple[Path, bytes]] = []
    for path in artifacts_ordered:
        direct, data, _ = _read_direct_file(path, label="Release artifact")
        snapshots.append((direct, data))
    names = [path.name for path, _ in snapshots]
    if len(names) != len(set(name.casefold() for name in names)):
        raise ReleaseError("Release artifact basenames must be unique")
    if any(
        name in {"", ".", ".."}
        or Path(name).name != name
        or "/" in name
        or "\\" in name
        for name in names
    ):
        raise ReleaseError("Release artifact name is unsafe")
    if (signing_private_key is None) != (signing_public_key is None):
        raise ReleaseError("Release signing requires both private and public keys")

    manifest = {
        "schema": 1,
        "kind": "psmatrix.release-manifest",
        "version": version,
        "created_at": _build_time(),
        "artifacts": [
            {
                "name": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for path, data in snapshots
        ],
    }
    payload: dict[str, Any] = {"manifest": manifest}
    if signing_private_key is not None and signing_public_key is not None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in manifest["artifacts"]
            ],
            "predicateType": "https://psmatrix.dev/attestation/release-manifest/v1",
            "predicate": manifest,
        }
        payload["attestation"] = create_dsse_envelope(
            statement, signing_private_key, signing_public_key
        )

    output = _direct_output_file(output, label="Release manifest output")
    atomic_write_json(output, payload)
    _, persisted, _ = _read_direct_file(output, label="Release manifest output")
    try:
        persisted_value = json.loads(persisted.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("Release manifest output is invalid after write") from exc
    if persisted_value != payload:
        raise ReleaseError("Release manifest output changed after write")
    return payload


def verify_release_manifest(
    manifest_path: Path,
    artifact_dir: Path,
    *,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    _, raw_manifest, _ = _read_direct_file(
        manifest_path, label="Release manifest"
    )
    try:
        value = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("Release manifest is malformed") from exc
    manifest = (
        value.get("manifest")
        if isinstance(value, dict) and isinstance(value.get("manifest"), dict)
        else None
    )
    if manifest is None or manifest.get("schema") != 1:
        raise ReleaseError("Release manifest is malformed")
    artifact_items = manifest.get("artifacts")
    if not isinstance(artifact_items, list) or not artifact_items:
        raise ReleaseError("Release manifest contains no artifacts")
    names = [
        str(item.get("name") or "")
        for item in artifact_items
        if isinstance(item, dict)
    ]
    if (
        len(names) != len(artifact_items)
        or len(names) != len(set(name.casefold() for name in names))
    ):
        raise ReleaseError("Release manifest artifact names are malformed or duplicated")

    artifact_dir = _direct_directory(
        artifact_dir, label="Release artifact directory"
    )
    verified: list[str] = []
    for item in artifact_items:
        if not isinstance(item, dict):
            raise ReleaseError("Release artifact metadata is malformed")
        name = str(item.get("name") or "")
        if (
            name in {"", ".", ".."}
            or Path(name).name != name
            or "/" in name
            or "\\" in name
        ):
            raise ReleaseError("Release manifest contains an unsafe artifact name")
        path, data, _ = _read_direct_file(
            artifact_dir / name, label=f"Release artifact {name}"
        )
        if len(data) != item.get("size") or hashlib.sha256(data).hexdigest() != item.get(
            "sha256"
        ):
            raise ReleaseError(f"Release artifact verification failed: {path.name}")
        verified.append(path.name)

    signature = None
    if signing_public_key is not None:
        envelope = value.get("attestation") if isinstance(value, dict) else None
        if not isinstance(envelope, dict):
            raise ReleaseError("Signed release manifest is missing its attestation")
        result = verify_dsse_envelope(envelope, signing_public_key)
        statement = result["statement"]
        if statement.get("predicate") != manifest:
            raise ReleaseError("Release signature does not bind the manifest")
        expected_subject = [
            {"name": item["name"], "digest": {"sha256": item["sha256"]}}
            for item in artifact_items
        ]
        if statement.get("subject") != expected_subject:
            raise ReleaseError("Release signature subject does not bind every artifact")
        signature = {"valid": True, "key_ids": result["key_ids"]}
    return {
        "valid": True,
        "version": manifest.get("version"),
        "artifacts": verified,
        "signature": signature,
    }


def verify_reproducible_build(first: Path, second: Path) -> dict[str, Any]:
    _, first_bytes, _ = _read_direct_file(first, label="First reproducibility artifact")
    _, second_bytes, _ = _read_direct_file(second, label="Second reproducibility artifact")
    if first_bytes != second_bytes:
        raise ReleaseError("Artifacts are not byte-for-byte reproducible")
    return {
        "reproducible": True,
        "sha256": hashlib.sha256(first_bytes).hexdigest(),
        "size": len(first_bytes),
    }
