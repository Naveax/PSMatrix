from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ASSET_NAME = "psmatrix-2.0.0-final-ga-attestation.zip"
SHA40 = set("0123456789abcdef")


class FinalGAAttestationPublicAssetError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _absolute(path: Path) -> Path:
    raw = Path(path).expanduser()
    return raw if raw.is_absolute() else Path.cwd() / raw


def _reject_symlink_components(path: Path, label: str) -> Path:
    raw = _absolute(path)
    for component in [raw, *raw.parents]:
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FinalGAAttestationPublicAssetError(f"unable to inspect {label}: {component}") from exc
        if stat.S_ISLNK(mode):
            raise FinalGAAttestationPublicAssetError(f"{label} may not traverse a symlink: {component}")
    return raw


def _safe_json(path: Path, label: str) -> tuple[dict[str, Any], Path]:
    raw = _reject_symlink_components(path, label)
    try:
        resolved = raw.resolve(strict=True)
        item = resolved.lstat()
        if not stat.S_ISREG(item.st_mode):
            raise FinalGAAttestationPublicAssetError(f"{label} must be a regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalGAAttestationPublicAssetError(f"unable to read {label}") from exc
    if not isinstance(value, dict):
        raise FinalGAAttestationPublicAssetError(f"{label} root must be an object")
    return value, resolved


def _validate_operation(value: dict[str, Any], operation_path: Path) -> str:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.final-ga-attestation-content-operation"
        or value.get("version") != "2.0.0"
        or value.get("status") != "PASS"
    ):
        raise FinalGAAttestationPublicAssetError("final attestation content operation identity/status mismatch")
    for field in (
        "exact_api_artifact_id_used",
        "safe_extraction_verified",
        "semantic_verifier_repository_owned",
        "final_ga_attestation_verified",
        "ga_eligible",
    ):
        if value.get(field) is not True:
            raise FinalGAAttestationPublicAssetError(f"final attestation content operation boundary failed: {field}")
    if value.get("semantic_verification_mutated_tree") is not False:
        raise FinalGAAttestationPublicAssetError("final attestation semantic verifier mutated the verified tree")
    head = str(value.get("execution_head") or "").lower()
    if len(head) != 40 or any(ch not in SHA40 for ch in head):
        raise FinalGAAttestationPublicAssetError("final attestation execution head is invalid")
    verification_raw = value.get("verification_receipt")
    verification_sha = str(value.get("verification_receipt_sha256") or "").lower()
    if not isinstance(verification_raw, str) or not verification_raw or len(verification_sha) != 64:
        raise FinalGAAttestationPublicAssetError("final attestation verification receipt reference is invalid")
    verification = Path(verification_raw).expanduser()
    if not verification.is_absolute():
        verification = operation_path.parent / verification
    verification_value, verification_path = _safe_json(verification, "final attestation verification receipt")
    if _sha256(verification_path) != verification_sha:
        raise FinalGAAttestationPublicAssetError("final attestation verification receipt digest mismatch")
    if (
        verification_value.get("schema") != 1
        or verification_value.get("kind") != "psmatrix.final-ga-attestation-bundle-verification"
        or verification_value.get("version") != "2.0.0"
        or verification_value.get("status") != "PASS"
        or verification_value.get("execution_control_head") != head
        or verification_value.get("private_key_material_absent") is not True
        or verification_value.get("dsse_cryptographically_verified") is not True
        or verification_value.get("root_release_authorities_independent") is not True
        or verification_value.get("final_ga_attestation_verified") is not True
        or verification_value.get("ga_eligible") is not True
    ):
        raise FinalGAAttestationPublicAssetError("final attestation verification receipt does not prove public-safe GA closure")
    return head


def _bundle_files(root: Path) -> list[tuple[str, Path, bytes]]:
    raw = _reject_symlink_components(root, "final attestation bundle root")
    try:
        resolved = raw.resolve(strict=True)
        root_info = resolved.lstat()
    except OSError as exc:
        raise FinalGAAttestationPublicAssetError("unable to inspect final attestation bundle root") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise FinalGAAttestationPublicAssetError("final attestation bundle root must be a real directory")
    required = {
        "final-ga-attestation-status.json",
        "final-ga-evaluator-candidate-status.json",
        "final-ga-run-provenance.json",
        "ga-policy.json",
        "psmatrix-2.0.0-final-ga.dsse.json",
        "psmatrix-2.0.0-final-ga-verification.json",
        "psmatrix-2.0.0-ga-root-public.pem",
        "SHA256SUMS.txt",
    }
    rows: list[tuple[str, Path, bytes]] = []
    for path in sorted(resolved.rglob("*")):
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise FinalGAAttestationPublicAssetError(f"unable to inspect attestation bundle member: {path.name}") from exc
        if stat.S_ISLNK(mode):
            raise FinalGAAttestationPublicAssetError(f"symlink found in verified attestation bundle: {path.name}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise FinalGAAttestationPublicAssetError(f"unsupported filesystem entry in verified attestation bundle: {path.name}")
        relative = path.relative_to(resolved).as_posix()
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise FinalGAAttestationPublicAssetError(f"unsafe attestation bundle member: {relative}")
        rows.append((relative, path, path.read_bytes()))
    names = {row[0] for row in rows}
    if not required.issubset(names):
        raise FinalGAAttestationPublicAssetError("verified attestation bundle is missing required public verification files")
    if not rows:
        raise FinalGAAttestationPublicAssetError("verified attestation bundle is empty")
    return rows


def _open_exclusive(path: Path):
    absolute = _reject_symlink_components(path, "final attestation public asset output")
    if absolute.name != ASSET_NAME:
        raise FinalGAAttestationPublicAssetError(f"final attestation public asset name must be {ASSET_NAME}")
    try:
        absolute.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FinalGAAttestationPublicAssetError("unable to inspect final attestation public asset output") from exc
    else:
        raise FinalGAAttestationPublicAssetError("final attestation public asset output must not already exist")
    parent = absolute.parent
    _reject_symlink_components(parent, "final attestation public asset output parent")
    try:
        resolved_parent = parent.resolve(strict=True)
        parent_info = resolved_parent.lstat()
    except OSError as exc:
        raise FinalGAAttestationPublicAssetError("final attestation public asset output parent must already exist") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise FinalGAAttestationPublicAssetError("final attestation public asset output parent must already exist")
    candidate = resolved_parent / absolute.name
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise FinalGAAttestationPublicAssetError("final attestation public asset must stay outside repository")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(candidate, flags, 0o600)
    info = os.fstat(fd)
    return os.fdopen(fd, "w+b"), candidate, (int(info.st_dev), int(info.st_ino))


def _write_json_once(path: Path, payload: dict[str, Any], label: str) -> Path:
    raw = _reject_symlink_components(path, label)
    parent = raw.parent
    try:
        resolved_parent = parent.resolve(strict=True)
        parent_info = resolved_parent.lstat()
    except OSError as exc:
        raise FinalGAAttestationPublicAssetError(f"{label} parent must already exist") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise FinalGAAttestationPublicAssetError(f"{label} parent must already exist")
    candidate = resolved_parent / raw.name
    _reject_symlink_components(candidate, label)
    try:
        candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FinalGAAttestationPublicAssetError(f"unable to inspect {label}") from exc
    else:
        raise FinalGAAttestationPublicAssetError(f"{label} must not already exist")
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        opened = os.fstat(fd)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if not stat.S_ISREG(opened.st_mode):
            raise FinalGAAttestationPublicAssetError(f"{label} is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        current = candidate.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FinalGAAttestationPublicAssetError(f"{label} changed type during write")
        if (int(current.st_dev), int(current.st_ino)) != identity:
            raise FinalGAAttestationPublicAssetError(f"{label} path changed identity during write")
        if candidate.read_text(encoding="utf-8") != text:
            raise FinalGAAttestationPublicAssetError(f"{label} read-back mismatch")
        return candidate
    except Exception:
        if fd is not None:
            os.close(fd)
        if identity is not None:
            try:
                current = candidate.lstat()
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISLNK(current.st_mode) and stat.S_ISREG(current.st_mode) and (int(current.st_dev), int(current.st_ino)) == identity:
                    candidate.unlink()
        raise


def build(operation_path: Path, bundle_root: Path, output: Path) -> dict[str, Any]:
    operation, resolved_operation = _safe_json(operation_path, "final attestation content operation")
    head = _validate_operation(operation, resolved_operation)
    rows = _bundle_files(bundle_root)
    handle, candidate, identity = _open_exclusive(output)
    success = False
    try:
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
            for relative, _, data in rows:
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, data)
        handle.flush()
        os.fsync(handle.fileno())
        path_info = os.lstat(candidate)
        if not stat.S_ISREG(path_info.st_mode) or (int(path_info.st_dev), int(path_info.st_ino)) != identity:
            raise FinalGAAttestationPublicAssetError("final attestation public asset path identity changed during creation")
        handle.seek(0)
        with zipfile.ZipFile(handle, "r") as archive:
            infos = archive.infolist()
            if [info.filename for info in infos] != [row[0] for row in rows]:
                raise FinalGAAttestationPublicAssetError("canonical attestation ZIP member order/set mismatch")
            for info, (relative, _, data) in zip(infos, rows):
                if info.filename != relative or info.is_dir() or archive.read(info) != data:
                    raise FinalGAAttestationPublicAssetError(f"canonical attestation ZIP member bytes mismatch: {relative}")
                if info.date_time != (1980, 1, 1, 0, 0, 0) or info.compress_type != zipfile.ZIP_STORED:
                    raise FinalGAAttestationPublicAssetError(f"canonical attestation ZIP metadata mismatch: {relative}")
        handle.close()
        digest = _sha256(candidate)
        size = candidate.stat().st_size
        if size <= 0:
            raise FinalGAAttestationPublicAssetError("canonical attestation ZIP is empty")
        success = True
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-public-release-asset",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": head,
            "source_attestation_operation_sha256": _sha256(resolved_operation),
            "asset_name": ASSET_NAME,
            "asset_path": str(candidate),
            "asset_size": size,
            "asset_sha256": digest,
            "github_digest": f"sha256:{digest}",
            "member_count": len(rows),
            "deterministic_zip_metadata_verified": True,
            "public_verification_files_present": True,
            "private_key_material_absent_verified_upstream": True,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_closed": False,
        }
    finally:
        if not handle.closed:
            handle.close()
        if not success:
            try:
                info = os.lstat(candidate)
                if stat.S_ISREG(info.st_mode) and (int(info.st_dev), int(info.st_ino)) == identity:
                    candidate.unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic public ZIP from independently verified final GA attestation content")
    parser.add_argument("--attestation-operation", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(args.attestation_operation, args.bundle_root, args.output)
        written = _write_json_once(args.receipt, value, "public attestation asset receipt")
        print(f"final_ga_attestation_public_asset=PASS asset={ASSET_NAME} members={value['member_count']}")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=false")
        print(f"receipt={written}")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile, FinalGAAttestationPublicAssetError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA attestation public asset build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())