from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import zipfile
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


def release_files(root: Path) -> list[Path]:
    root = root.resolve()
    result = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in _EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.is_symlink():
            raise ReleaseError(f"Release source contains a symlink: {relative}")
        if path.is_file():
            result.append(path)
    return sorted(result, key=lambda item: item.relative_to(root).as_posix())


def _mode(path: Path) -> int:
    executable = bool(path.stat().st_mode & stat.S_IXUSR)
    return 0o100755 if executable else 0o100644


def build_reproducible_source(root: Path, output_dir: Path, *, name: str) -> dict[str, Any]:
    root = root.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    files = release_files(root)
    if not files:
        raise ReleaseError("Release source tree is empty")
    zip_path = output_dir / f"{name}-source.zip"
    tar_path = output_dir / f"{name}-source.tar.gz"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = f"{name}/{path.relative_to(root).as_posix()}"
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = _mode(path) << 16
            archive.writestr(info, path.read_bytes())
    atomic_write_bytes(zip_path, zip_buffer.getvalue())
    tar_raw = io.BytesIO()
    with tarfile.open(fileobj=tar_raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in files:
            relative = f"{name}/{path.relative_to(root).as_posix()}"
            info = tarfile.TarInfo(relative)
            data = path.read_bytes()
            info.size = len(data)
            info.mode = 0o755 if _mode(path) == 0o100755 else 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(data))
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
        gz.write(tar_raw.getvalue())
    atomic_write_bytes(tar_path, gz_buffer.getvalue())
    return {
        "zip": {"path": str(zip_path), "sha256": sha256_file(zip_path), "size": zip_path.stat().st_size},
        "tar_gz": {"path": str(tar_path), "sha256": sha256_file(tar_path), "size": tar_path.stat().st_size},
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
    artifacts = sorted({path.resolve() for path in artifacts}, key=lambda path: path.name)
    if not artifacts or any(not path.is_file() for path in artifacts):
        raise ReleaseError("Release artifacts are missing")
    names = [path.name for path in artifacts]
    if len(names) != len(set(name.casefold() for name in names)):
        raise ReleaseError("Release artifact basenames must be unique")
    if any(name in {"", ".", ".."} or Path(name).name != name or "/" in name or "\\" in name for name in names):
        raise ReleaseError("Release artifact name is unsafe")
    if (signing_private_key is None) != (signing_public_key is None):
        raise ReleaseError("Release signing requires both private and public keys")
    manifest = {
        "schema": 1,
        "kind": "psmatrix.release-manifest",
        "version": version,
        "created_at": _build_time(),
        "artifacts": [
            {"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}
            for path in artifacts
        ],
    }
    payload: dict[str, Any] = {"manifest": manifest}
    if signing_private_key is not None and signing_public_key is not None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": item["name"], "digest": {"sha256": item["sha256"]}} for item in manifest["artifacts"]],
            "predicateType": "https://psmatrix.dev/attestation/release-manifest/v1",
            "predicate": manifest,
        }
        payload["attestation"] = create_dsse_envelope(statement, signing_private_key, signing_public_key)
    atomic_write_json(output.resolve(), payload)
    return payload


def verify_release_manifest(manifest_path: Path, artifact_dir: Path, *, signing_public_key: Path | None = None) -> dict[str, Any]:
    from .util import read_json
    value = read_json(manifest_path.resolve())
    manifest = value.get("manifest") if isinstance(value, dict) and isinstance(value.get("manifest"), dict) else None
    if manifest is None or manifest.get("schema") != 1:
        raise ReleaseError("Release manifest is malformed")
    artifact_items = manifest.get("artifacts")
    if not isinstance(artifact_items, list) or not artifact_items:
        raise ReleaseError("Release manifest contains no artifacts")
    names = [str(item.get("name") or "") for item in artifact_items if isinstance(item, dict)]
    if len(names) != len(artifact_items) or len(names) != len(set(name.casefold() for name in names)):
        raise ReleaseError("Release manifest artifact names are malformed or duplicated")
    verified = []
    for item in artifact_items:
        if not isinstance(item, dict):
            raise ReleaseError("Release artifact metadata is malformed")
        name = str(item.get("name") or "")
        if name in {"", ".", ".."} or Path(name).name != name or "/" in name or "\\" in name:
            raise ReleaseError("Release manifest contains an unsafe artifact name")
        path = artifact_dir.resolve() / name
        if not path.is_file() or path.stat().st_size != item.get("size") or sha256_file(path) != item.get("sha256"):
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
        expected_subject = [{"name": item["name"], "digest": {"sha256": item["sha256"]}} for item in artifact_items]
        if statement.get("subject") != expected_subject:
            raise ReleaseError("Release signature subject does not bind every artifact")
        signature = {"valid": True, "key_ids": result["key_ids"]}
    return {"valid": True, "version": manifest.get("version"), "artifacts": verified, "signature": signature}


def verify_reproducible_build(first: Path, second: Path) -> dict[str, Any]:
    first = first.resolve()
    second = second.resolve()
    if not first.is_file() or not second.is_file():
        raise ReleaseError("Reproducibility comparison artifact is missing")
    first_hash = sha256_file(first)
    second_hash = sha256_file(second)
    if first_hash != second_hash or first.stat().st_size != second.stat().st_size:
        raise ReleaseError("Artifacts are not byte-for-byte reproducible")
    return {"reproducible": True, "sha256": first_hash, "size": first.stat().st_size}
