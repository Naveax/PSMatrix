from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope
from .util import atomic_write_bytes


class DeploymentError(PSMatrixError):
    """Raised when a Windows worker deployment package is incomplete or unsafe."""


def _build_time() -> str:
    from datetime import UTC, datetime

    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise DeploymentError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise DeploymentError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(epoch, UTC).isoformat()


_REQUIRED_FILES = (
    "PSMatrixWorkerService.cs",
    "install-worker.ps1",
    "uninstall-worker.ps1",
    "rotate-worker-credentials.ps1",
    "health-check.ps1",
    "worker_harness.ps1",
)
_SUPPORTED_WINDOWS_POWERSHELL = ("4.0", "5.0", "5.1")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
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
            raise DeploymentError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise DeploymentError(
                f"{label} cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise DeploymentError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise DeploymentError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise DeploymentError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise DeploymentError(f"{label} must be a direct directory: {candidate}")
    return candidate


def _existing_direct_directory(path: Path, *, label: str) -> Path | None:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DeploymentError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info):
        raise DeploymentError(f"{label} cannot use symlink or reparse indirection: {candidate}")
    if not stat.S_ISDIR(info.st_mode):
        return None
    return candidate


def _direct_regular_exists(path: Path, *, label: str) -> bool:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DeploymentError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info):
        raise DeploymentError(f"{label} cannot use symlink or reparse indirection: {candidate}")
    return stat.S_ISREG(info.st_mode)


def _read_direct_file(path: Path, *, label: str) -> tuple[Path, bytes, os.stat_result]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise DeploymentError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise DeploymentError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise DeploymentError(f"{label} must be a direct regular file: {candidate}")

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
                raise DeploymentError(f"{label} changed while opening: {candidate}")
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
                raise DeploymentError(f"{label} changed while reading: {candidate}")
    except DeploymentError:
        raise
    except OSError as exc:
        raise DeploymentError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise DeploymentError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISREG(final.st_mode)
        or not _same_file(final, opened_after)
    ):
        raise DeploymentError(f"{label} changed after read: {candidate}")
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
        raise DeploymentError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise DeploymentError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _write_verified_bytes(path: Path, data: bytes, *, label: str) -> tuple[Path, bytes]:
    target = _direct_output_file(path, label=label)
    atomic_write_bytes(target, data)
    persisted_path, persisted, _ = _read_direct_file(target, label=label)
    if persisted != data:
        raise DeploymentError(f"{label} changed after write")
    return persisted_path, persisted


def _safe_archive_parts(filename: str) -> tuple[str, ...]:
    name = PurePosixPath(filename)
    if (
        name.is_absolute()
        or ".." in name.parts
        or "." in name.parts
        or "\\" in filename
        or "\x00" in filename
        or not name.parts
    ):
        raise DeploymentError(f"Deployment package contains an unsafe entry: {filename}")
    result: list[str] = []
    for component in name.parts:
        if not component or component.endswith((" ", ".")) or ":" in component:
            raise DeploymentError(f"Deployment package contains a Windows-unsafe entry: {filename}")
        base = component.split(".", 1)[0].upper()
        if base in _WINDOWS_RESERVED_NAMES:
            raise DeploymentError(f"Deployment package contains a reserved Windows entry: {filename}")
        result.append(component)
    return tuple(result)


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _template(version: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "worker_id": f"REPLACE-WINDOWS-PS-{version}",
        "host": "0.0.0.0",
        "port": 9443,
        "tls": {
            "certificate": "../credentials/certificate.pem",
            "private_key": "../credentials/private-key.pem",
            "client_ca": "../credentials/ca-certificate.pem",
        },
        "signing": {
            "private_key": "../signing/worker-ed25519-private.pem",
            "public_key": "../signing/worker-ed25519-public.pem",
        },
        "controller": {
            "identity": "REPLACE-CONTROLLER-ID",
            "public_key": "../trust/controller-ed25519-public.pem",
            "certificate_sha256": "REPLACE-CONTROLLER-CERTIFICATE-SHA256",
        },
        "workspace_root": "../workspace",
        "runtime": {
            "executable": "powershell.exe",
            "version": version,
        },
        "reset": {
            "required": False,
            "before": None,
            "after": None,
            "note": "Production VM reset is controller-managed by a signed snapshot adapter.",
        },
        "max_request_bytes": 100663296,
        "transfer_chunk_size": 1048576,
        "inline_artifact_limit": 8388608,
    }


def _find_complete_worker_root(candidates: list[Path]) -> Path:
    first_existing: Path | None = None
    for candidate in candidates:
        direct = _existing_direct_directory(candidate, label="Windows deployment worker directory")
        if direct is None:
            continue
        if first_existing is None:
            first_existing = direct
        if all(
            _direct_regular_exists(direct / name, label=f"Windows deployment file {name}")
            for name in _REQUIRED_FILES
        ):
            return direct
    missing = [
        name
        for name in _REQUIRED_FILES
        if first_existing is None
        or not _direct_regular_exists(
            first_existing / name, label=f"Windows deployment file {name}"
        )
    ]
    raise DeploymentError("Windows deployment files are missing: " + ", ".join(missing))


def _first_direct_directory(candidates: list[Path], *, label: str) -> Path | None:
    for candidate in candidates:
        direct = _existing_direct_directory(candidate, label=label)
        if direct is not None:
            return direct
    return None


def _fixture_snapshots(root: Path) -> list[tuple[str, bytes]]:
    snapshots: list[tuple[str, bytes]] = []
    walker = os.walk(root, topdown=True, followlinks=False)
    for current_raw, dirnames, filenames in walker:
        current = _direct_directory(Path(current_raw), label="Windows deployment fixture directory")
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            candidate = current / name
            info = candidate.lstat()
            if _is_link_or_reparse(info):
                raise DeploymentError(
                    f"Windows deployment fixture tree contains symlink or reparse indirection: {candidate}"
                )
            if stat.S_ISDIR(info.st_mode):
                kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            candidate = current / name
            info = candidate.lstat()
            if _is_link_or_reparse(info):
                raise DeploymentError(
                    f"Windows deployment fixture tree contains symlink or reparse indirection: {candidate}"
                )
            if not stat.S_ISREG(info.st_mode):
                continue
            direct, data, _ = _read_direct_file(candidate, label="Windows deployment fixture")
            snapshots.append((direct.relative_to(root).as_posix(), data))
    snapshots.sort(key=lambda item: item[0])
    return snapshots


def build_windows_worker_package(
    source_root: Path,
    output: Path,
    *,
    version: str,
    wheel: Path | None = None,
    signing_private_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    source_root = _direct_directory(source_root, label="Windows deployment source root")
    package_root = Path(__file__).absolute().parent
    worker_root = _find_complete_worker_root(
        [
            source_root / "workers" / "windows",
            source_root / "src" / "psmatrix" / "windows",
            package_root / "windows",
        ]
    )
    if (signing_private_key is None) != (signing_public_key is None):
        raise DeploymentError("Deployment signing requires both private and public keys")

    entries: dict[str, bytes] = {}
    for name in _REQUIRED_FILES:
        _, data, _ = _read_direct_file(
            worker_root / name, label=f"Windows deployment file {name}"
        )
        entries[f"worker/{name}"] = data
    for ps_version in _SUPPORTED_WINDOWS_POWERSHELL:
        entries[f"config/worker-{ps_version}.template.json"] = (
            json.dumps(_template(ps_version), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    snapshot_root = _first_direct_directory(
        [
            source_root / "workers" / "snapshot",
            source_root / "src" / "psmatrix" / "snapshot_tools",
            package_root / "snapshot_tools",
        ],
        label="Windows deployment snapshot tools directory",
    )
    if snapshot_root is not None:
        for name in sorted(os.listdir(snapshot_root)):
            tool = snapshot_root / name
            if tool.suffix.casefold() != ".ps1":
                continue
            if not _direct_regular_exists(tool, label="Windows deployment snapshot tool"):
                continue
            direct, data, _ = _read_direct_file(tool, label="Windows deployment snapshot tool")
            entries[f"snapshot/{direct.name}"] = data

    fixture_sets = {
        "legacy": [
            source_root / "fixtures" / "windows",
            source_root / "src" / "psmatrix" / "windows" / "fixtures",
            package_root / "windows" / "fixtures",
        ],
        "authoritative": [
            source_root / "fixtures" / "windows-authoritative",
            source_root / "src" / "psmatrix" / "windows" / "fixtures-authoritative",
            package_root / "windows" / "fixtures-authoritative",
        ],
    }
    for fixture_kind, candidates in fixture_sets.items():
        fixture_root = _first_direct_directory(
            candidates, label=f"Windows deployment {fixture_kind} fixture directory"
        )
        if fixture_root is None:
            continue
        for relative, data in _fixture_snapshots(fixture_root):
            entries[f"fixtures/{fixture_kind}/{relative}"] = data

    if wheel is not None:
        wheel_candidate = _lexical_absolute(wheel)
        if wheel_candidate.suffix != ".whl":
            raise DeploymentError("Windows deployment wheel is invalid")
        wheel_path, wheel_bytes, _ = _read_direct_file(
            wheel_candidate, label="Windows deployment wheel"
        )
        entries[f"python/{wheel_path.name}"] = wheel_bytes

    file_manifest = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name, data in sorted(entries.items())
    }
    manifest = {
        "schema": 1,
        "kind": "psmatrix.windows-worker-deployment",
        "tool_version": version,
        "created_at": _build_time(),
        "supported_runtimes": [
            f"windows-powershell-{item}" for item in _SUPPORTED_WINDOWS_POWERSHELL
        ],
        "files": file_manifest,
        "installation": {
            "entrypoint": "worker/install-worker.ps1",
            "requires_administrator": True,
            "service_host": "worker/PSMatrixWorkerService.cs",
            "offline_wheel": next(
                (
                    name
                    for name in entries
                    if name.startswith("python/") and name.endswith(".whl")
                ),
                None,
            ),
        },
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    entries["manifest.json"] = manifest_bytes
    if signing_private_key is not None and signing_public_key is not None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": name, "digest": {"sha256": meta["sha256"]}}
                for name, meta in sorted(file_manifest.items())
            ],
            "predicateType": "https://psmatrix.dev/attestation/windows-worker-deployment/v1",
            "predicate": manifest,
        }
        envelope = create_dsse_envelope(
            statement, signing_private_key, signing_public_key
        )
        entries["manifest.dsse.json"] = (
            json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, data in sorted(entries.items()):
            archive.writestr(_zip_info(name), data)
    output_path, output_bytes = _write_verified_bytes(
        output, buffer.getvalue(), label="Windows deployment package output"
    )
    return {
        "output": str(output_path),
        "sha256": hashlib.sha256(output_bytes).hexdigest(),
        "size": len(output_bytes),
        "signed": signing_private_key is not None,
        "supported_runtimes": manifest["supported_runtimes"],
        "file_count": len(entries),
    }


def verify_windows_worker_package(
    package: Path, *, signing_public_key: Path | None = None
) -> dict[str, Any]:
    from .signing import verify_dsse_envelope

    package_path, package_bytes, _ = _read_direct_file(
        package, label="Windows deployment package"
    )
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 4096:
            raise DeploymentError("Deployment package entry count is invalid")
        names = [info.filename for info in infos]
        if len(names) != len(set(name.casefold() for name in names)):
            raise DeploymentError("Deployment package contains duplicate paths")
        total_size = 0
        for info in infos:
            _safe_archive_parts(info.filename)
            if info.flag_bits & 0x1:
                raise DeploymentError("Deployment package contains an encrypted entry")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise DeploymentError(
                    f"Deployment package contains a symlink entry: {info.filename}"
                )
            if info.file_size > 128 * 1024 * 1024:
                raise DeploymentError("Deployment package entry is too large")
            total_size += info.file_size
            if total_size > 512 * 1024 * 1024:
                raise DeploymentError("Deployment package expands beyond the supported limit")
        try:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentError("Deployment manifest is missing or malformed") from exc
        files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
        allowed_entries = set(files) | {"manifest.json", "manifest.dsse.json"}
        unexpected = sorted(set(names) - allowed_entries)
        if unexpected:
            raise DeploymentError(
                "Deployment package contains unlisted entries: " + ", ".join(unexpected)
            )
        for name, meta in files.items():
            if not isinstance(meta, dict):
                raise DeploymentError("Deployment file metadata is malformed")
            _safe_archive_parts(str(name))
            try:
                raw = archive.read(name)
            except KeyError as exc:
                raise DeploymentError(f"Deployment file is missing: {name}") from exc
            if len(raw) != meta.get("size") or hashlib.sha256(raw).hexdigest() != meta.get(
                "sha256"
            ):
                raise DeploymentError(f"Deployment file integrity failed: {name}")
        signed = "manifest.dsse.json" in names
        verification = None
        if signing_public_key is not None:
            if not signed:
                raise DeploymentError("Deployment package is not signed")
            try:
                envelope = json.loads(
                    archive.read("manifest.dsse.json").decode("utf-8")
                )
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DeploymentError("Deployment signature envelope is malformed") from exc
            verification = verify_dsse_envelope(envelope, signing_public_key)
            predicate = verification["statement"].get("predicate")
            if predicate != manifest:
                raise DeploymentError("Deployment signature does not bind the manifest")
    return {
        "valid": True,
        "package": str(package_path),
        "sha256": hashlib.sha256(package_bytes).hexdigest(),
        "signed": signed,
        "signature": (
            {"valid": True, "key_ids": verification["key_ids"]}
            if verification
            else None
        ),
        "supported_runtimes": manifest.get("supported_runtimes"),
        "files": len(files),
    }
