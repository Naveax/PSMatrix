from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ASSET_NAME = "psmatrix-2.0.0-final-ga-attestation.zip"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)


class FinalGAAttestationPublicAssetVerificationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_symlink_components(path: Path, label: str) -> None:
    current = path.expanduser().absolute()
    while True:
        if current.exists() and current.is_symlink():
            raise FinalGAAttestationPublicAssetVerificationError(f"{label} may not traverse a symlink: {current}")
        if current.parent == current:
            break
        current = current.parent


def _json(path: Path, label: str) -> tuple[dict[str, Any], Path]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FinalGAAttestationPublicAssetVerificationError(f"{label} is missing")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FinalGAAttestationPublicAssetVerificationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FinalGAAttestationPublicAssetVerificationError(f"{label} root must be an object")
    return value, resolved


def _bundle_state(root: Path) -> tuple[str, list[dict[str, Any]], dict[str, bytes]]:
    _reject_symlink_components(root, "final attestation bundle root")
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise FinalGAAttestationPublicAssetVerificationError("final attestation bundle root is missing")
    files: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            raise FinalGAAttestationPublicAssetVerificationError(f"symlink found in final attestation bundle: {path.name}")
        if path.is_file():
            relative = path.relative_to(resolved).as_posix()
            if relative.startswith("/") or ".." in Path(relative).parts:
                raise FinalGAAttestationPublicAssetVerificationError(f"unsafe final attestation bundle path: {relative}")
            data = path.read_bytes()
            if any(marker in data for marker in PRIVATE_MARKERS):
                raise FinalGAAttestationPublicAssetVerificationError(f"private-key material found in final attestation bundle: {relative}")
            digest = hashlib.sha256(data).hexdigest()
            files.append({"path": relative, "size": len(data), "sha256": digest})
            payloads[relative] = data
    if not files:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation bundle is empty")
    tree = hashlib.sha256()
    for row in files:
        tree.update(f"{row['path']}\0{row['size']}\0{row['sha256']}\n".encode("utf-8"))
    return tree.hexdigest(), files, payloads


def verify(operation: dict[str, Any], public_asset_receipt: dict[str, Any], bundle_root: Path) -> dict[str, Any]:
    if (
        operation.get("schema") != 1
        or operation.get("kind") != "psmatrix.final-ga-attestation-content-operation"
        or operation.get("version") != "2.0.0"
        or operation.get("status") != "PASS"
        or operation.get("final_ga_attestation_verified") is not True
        or operation.get("ga_eligible") is not True
        or operation.get("safe_extraction_verified") is not True
        or operation.get("semantic_verifier_repository_owned") is not True
        or operation.get("semantic_verification_mutated_tree") is not False
    ):
        raise FinalGAAttestationPublicAssetVerificationError("final attestation content operation boundary mismatch")
    head = str(operation.get("execution_head") or "").lower()
    expected_tree = str(operation.get("materialized_tree_sha256") or "").lower()
    expected_count = operation.get("materialized_file_count")
    if SHA40.fullmatch(head) is None or SHA256.fullmatch(expected_tree) is None or type(expected_count) is not int or expected_count <= 0:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation operation tree/head metadata is invalid")

    if (
        public_asset_receipt.get("schema") != 1
        or public_asset_receipt.get("kind") != "psmatrix.final-ga-attestation-public-release-asset"
        or public_asset_receipt.get("version") != "2.0.0"
        or public_asset_receipt.get("status") != "PASS"
        or public_asset_receipt.get("execution_head") != head
        or public_asset_receipt.get("asset_name") != ASSET_NAME
        or public_asset_receipt.get("deterministic_zip_metadata_verified") is not True
        or public_asset_receipt.get("public_verification_files_present") is not True
        or public_asset_receipt.get("final_ga_attestation_verified") is not True
        or public_asset_receipt.get("ga_eligible") is not True
    ):
        raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset receipt boundary mismatch")

    tree_sha, files, payloads = _bundle_state(bundle_root)
    if tree_sha != expected_tree or len(files) != expected_count:
        raise FinalGAAttestationPublicAssetVerificationError("current final attestation bundle differs from independently verified materialized tree")

    asset_raw = public_asset_receipt.get("asset_path")
    expected_sha = str(public_asset_receipt.get("asset_sha256") or "").lower()
    expected_size = public_asset_receipt.get("asset_size")
    if not isinstance(asset_raw, str) or not asset_raw or SHA256.fullmatch(expected_sha) is None or type(expected_size) is not int or expected_size <= 0:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset receipt digest/path metadata is invalid")
    asset = Path(asset_raw).expanduser()
    _reject_symlink_components(asset, "final attestation public asset")
    asset = asset.resolve()
    if not asset.is_file() or asset.name != ASSET_NAME:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset file identity mismatch")
    if _sha256(asset) != expected_sha or asset.stat().st_size != expected_size:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset bytes differ from producer receipt")

    try:
        with zipfile.ZipFile(asset, "r") as archive:
            infos = archive.infolist()
            names = [row["path"] for row in files]
            if [info.filename for info in infos] != names:
                raise FinalGAAttestationPublicAssetVerificationError("final attestation public ZIP member order/set mismatch")
            for info in infos:
                if info.is_dir() or info.filename not in payloads:
                    raise FinalGAAttestationPublicAssetVerificationError(f"unexpected final attestation ZIP member: {info.filename}")
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise FinalGAAttestationPublicAssetVerificationError(f"symlink member found in final attestation public ZIP: {info.filename}")
                if info.date_time != (1980, 1, 1, 0, 0, 0) or info.compress_type != zipfile.ZIP_STORED:
                    raise FinalGAAttestationPublicAssetVerificationError(f"noncanonical final attestation ZIP metadata: {info.filename}")
                if archive.read(info) != payloads[info.filename]:
                    raise FinalGAAttestationPublicAssetVerificationError(f"final attestation ZIP member differs from current verified bundle: {info.filename}")
    except zipfile.BadZipFile as exc:
        raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset is not a valid ZIP") from exc

    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-attestation-public-release-asset-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": head,
        "asset_name": ASSET_NAME,
        "asset_path": str(asset),
        "asset_size": expected_size,
        "asset_sha256": expected_sha,
        "github_digest": f"sha256:{expected_sha}",
        "member_count": len(files),
        "current_bundle_tree_sha256": tree_sha,
        "current_bundle_matches_verified_operation": True,
        "current_asset_matches_producer_receipt": True,
        "zip_members_match_current_verified_bundle": True,
        "private_key_material_absent": True,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "release_closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Reverify the canonical final GA attestation public release asset against current verified bundle bytes")
    parser.add_argument("--attestation-operation", type=Path, required=True)
    parser.add_argument("--public-asset-receipt", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        operation, _ = _json(args.attestation_operation, "final attestation content operation")
        receipt, _ = _json(args.public_asset_receipt, "final attestation public asset receipt")
        value = verify(operation, receipt, args.bundle_root)
        if args.output.exists():
            raise FinalGAAttestationPublicAssetVerificationError("final attestation public asset verification output must not already exist")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_ga_attestation_public_asset_verification=PASS asset={ASSET_NAME} members={value['member_count']}")
        print("current_bundle_matches_verified_operation=true")
        print("zip_members_match_current_verified_bundle=true")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, FinalGAAttestationPublicAssetVerificationError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA attestation public asset verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
