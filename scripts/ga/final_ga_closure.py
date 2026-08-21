#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

LEGACY_PATH = Path(__file__).with_name("final_ga_closure_legacy.py")
_spec = importlib.util.spec_from_file_location("psmatrix_final_ga_closure_legacy", LEGACY_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load preserved final GA closure implementation")
_legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)

ClosureError = _legacy.ClosureError
REQUIRED_GATES = _legacy.REQUIRED_GATES
CLOSURE_PREDICATE = _legacy.CLOSURE_PREDICATE
validate_source_version = _legacy.validate_source_version
validate_validation_summary = _legacy.validate_validation_summary
validate_evaluation = _legacy.validate_evaluation
_ensure_independent_final_signer = _legacy._ensure_independent_final_signer
exact_commit = _legacy.exact_commit

_VERSION = "2.0.0"
_SBOM_NAME = f"psmatrix-{_VERSION}-sbom.cdx.json"
_CHECKSUMS_NAME = f"psmatrix-{_VERSION}-SHA256SUMS"
_EXPECTED_SIGNED_ARTIFACTS = {
    f"psmatrix-{_VERSION}-source.zip",
    f"psmatrix-{_VERSION}-source.tar.gz",
    f"psmatrix-{_VERSION}-py3-none-any.whl",
    f"psmatrix-{_VERSION}-windows-workers.zip",
    f"psmatrix-{_VERSION}-windows-certification-kit.zip",
    f"psmatrix-{_VERSION}-windows-provisioning-kit.zip",
}
_LEGACY_BUILD_CLOSURE_STATEMENT = _legacy.build_closure_statement
_CONTEXT_MODE: str | None = None
_CONTEXT_METADATA_ROOT: Path | None = None
_LAST_METADATA: dict[str, dict[str, Any]] | None = None


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _reject_symlink_components(path: Path, label: str) -> Path:
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ClosureError(f"{label} contains a symlink component")
    return absolute


def _safe_input_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise ClosureError(f"{label} is missing or unsafe")
    return resolved


def _safe_input_directory(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise ClosureError(f"{label} is missing or unsafe")
    return resolved


def _safe_output_directory(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise ClosureError(f"{label} must be a directory")
    return resolved


def _safe_output_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if resolved.exists() and not resolved.is_file():
        raise ClosureError(f"{label} must be a file")
    return resolved


def _safe_policy_resolve(base: Path, value: Any, label: str, *, directory: bool = False) -> Path:
    text = str(value or "")
    if not text or "\x00" in text or len(text) > 4096:
        raise ClosureError(f"{label} path is missing or invalid")
    safe_base = _safe_input_directory(base, "GA policy root")
    requested = Path(text)
    candidate = requested if requested.is_absolute() else safe_base / requested
    candidate = _reject_symlink_components(candidate, label)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(safe_base)
    except ValueError as exc:
        raise ClosureError(f"{label} escapes the policy root") from exc
    if directory:
        if not resolved.is_dir():
            raise ClosureError(f"{label} directory is missing")
    elif not resolved.is_file():
        raise ClosureError(f"{label} file is missing")
    return resolved


def _prepare_sign_args(args: Any) -> Any:
    safe = copy.copy(args)
    safe.policy = _safe_input_file(args.policy, "GA policy")
    safe.source_root = _safe_input_directory(args.source_root, "source root")
    safe.private_key = _safe_input_file(args.private_key, "final GA private key")
    safe.public_key = _safe_input_file(args.public_key, "final GA public key")
    safe.output_dir = _safe_output_directory(args.output_dir, "final GA closure output")
    return safe


def _prepare_verify_args(args: Any) -> Any:
    safe = copy.copy(args)
    safe.policy = _safe_input_file(args.policy, "GA policy")
    safe.source_root = _safe_input_directory(args.source_root, "source root")
    safe.evaluation = _safe_input_file(args.evaluation, "Production GA evaluation")
    safe.ga_attestation = _safe_input_file(args.ga_attestation, "Production GA attestation")
    safe.closure_attestation = _safe_input_file(args.closure_attestation, "final closure attestation")
    safe.public_key = _safe_input_file(args.public_key, "final GA public key")
    safe.output = _safe_output_file(args.output, "final closure verification output") if args.output is not None else None
    return safe


# Keep the preserved signing implementation, but replace its resolve-first policy path helper
# with the fail-closed lexical-component check used by the active wrapper.
_legacy._resolve = _safe_policy_resolve


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_items(policy: dict[str, Any], base: Path) -> tuple[Path, Path, dict[str, dict[str, Any]]]:
    record = _legacy._policy_record(policy, "signed-release")
    manifest_path = _legacy._resolve(base, record.get("manifest"), "signed release manifest")
    artifact_dir = _legacy._resolve(base, record.get("artifact_dir"), "release artifact", directory=True)
    root = _legacy.read_json(manifest_path)
    manifest = root.get("manifest") if isinstance(root, dict) and isinstance(root.get("manifest"), dict) else None
    if manifest is None or manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.release-manifest":
        raise ClosureError("signed release manifest identity is invalid")
    if manifest.get("version") != _VERSION:
        raise ClosureError("signed release manifest is not final version 2.0.0")
    raw_items = manifest.get("artifacts")
    if not isinstance(raw_items, list) or len(raw_items) != 6:
        raise ClosureError("signed release manifest must contain exactly six distribution artifacts")

    items: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            raise ClosureError("signed release artifact metadata is malformed")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = item.get("size")
        if (
            not name
            or Path(name).name != name
            or name not in _EXPECTED_SIGNED_ARTIFACTS
            or _legacy.SHA256_RE.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise ClosureError(f"signed release artifact identity is invalid: {name!r}")
        key = name.casefold()
        if key in items:
            raise ClosureError("signed release artifact names are duplicated")
        path = artifact_dir / name
        if not path.is_file() or path.is_symlink():
            raise ClosureError(f"signed release artifact is missing or unsafe: {name}")
        if path.stat().st_size != size or _legacy.sha256_file(path) != digest:
            raise ClosureError(f"signed release artifact digest mismatch: {name}")
        items[key] = {"name": name, "sha256": digest, "size": size, "path": path}

    observed = {item["name"] for item in items.values()}
    if observed != _EXPECTED_SIGNED_ARTIFACTS:
        raise ClosureError("signed release manifest distribution artifact set is not exact")
    return manifest_path, artifact_dir, items


def validate_release_inventory(policy: dict[str, Any], base: Path) -> dict[str, Any]:
    """Validate only the release-authority-signed six-artifact distribution inventory."""
    manifest_path, artifact_dir, keyed = _manifest_items(policy, base)
    items = sorted(keyed.values(), key=lambda item: item["name"].casefold())
    by_name = {item["name"]: item for item in items}
    return {
        "manifest_path": manifest_path,
        "manifest_sha256": _legacy.sha256_file(manifest_path),
        "artifact_dir": artifact_dir,
        "artifacts": [
            {"name": item["name"], "sha256": item["sha256"], "size": item["size"]}
            for item in items
        ],
        "source_zip": {k: by_name[f"psmatrix-{_VERSION}-source.zip"][k] for k in ("name", "sha256", "size")},
        "source_tar_gz": {k: by_name[f"psmatrix-{_VERSION}-source.tar.gz"][k] for k in ("name", "sha256", "size")},
        "wheel": {k: by_name[f"psmatrix-{_VERSION}-py3-none-any.whl"][k] for k in ("name", "sha256", "size")},
        "signed_release_artifact_count": 6,
    }


def _metadata_payloads(release: dict[str, Any]) -> dict[str, bytes]:
    signed = release.get("artifacts")
    if not isinstance(signed, list) or len(signed) != 6:
        raise ClosureError("supply-chain metadata requires exactly six verified signed release artifacts")
    ordered = sorted(signed, key=lambda item: str(item["name"]).casefold())
    checksum_text = "".join(f"{item['sha256']}  {item['name']}\n" for item in ordered)

    manifest_digest = str(release.get("manifest_sha256") or "")
    if _legacy.SHA256_RE.fullmatch(manifest_digest) is None:
        raise ClosureError("signed release manifest digest is invalid for SBOM derivation")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://psmatrix.dev/release/{_VERSION}/{manifest_digest}")
    components = []
    for item in ordered:
        components.append(
            {
                "bom-ref": f"urn:psmatrix:artifact:sha256:{item['sha256']}",
                "type": "file",
                "name": item["name"],
                "version": _VERSION,
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                "properties": [
                    {"name": "psmatrix:artifact:size", "value": str(item["size"])},
                    {"name": "psmatrix:release-authority-signed", "value": "true"},
                ],
            }
        )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "psmatrix",
                "version": _VERSION,
                "properties": [
                    {"name": "psmatrix:signed-release-manifest-sha256", "value": manifest_digest},
                    {"name": "psmatrix:derivation", "value": "verified-signed-release-inventory"},
                ],
            }
        },
        "components": components,
        "dependencies": [],
    }
    sbom_text = json.dumps(sbom, indent=2, sort_keys=True) + "\n"
    return {
        _SBOM_NAME: sbom_text.encode("utf-8"),
        _CHECKSUMS_NAME: checksum_text.encode("utf-8"),
    }


def derive_supply_chain_metadata(release: dict[str, Any], output_root: Path) -> dict[str, dict[str, Any]]:
    root = _safe_output_directory(output_root, "closure metadata output root")
    root.mkdir(parents=True, exist_ok=True)
    result: dict[str, dict[str, Any]] = {}
    for name, data in _metadata_payloads(release).items():
        path = root / name
        if path.exists() and path.is_symlink():
            raise ClosureError(f"closure metadata destination cannot be a symlink: {name}")
        _legacy.atomic_text(path, data.decode("utf-8"))
        observed = path.read_bytes()
        if observed != data:
            raise ClosureError(f"deterministic closure metadata write mismatch: {name}")
        result[name] = {
            "name": name,
            "sha256": _sha256_bytes(data),
            "size": len(data),
            "path": path,
        }
    return result


def verify_supply_chain_metadata(release: dict[str, Any], metadata_root: Path) -> dict[str, dict[str, Any]]:
    root = _safe_input_directory(metadata_root, "closure metadata root")
    result: dict[str, dict[str, Any]] = {}
    for name, expected in _metadata_payloads(release).items():
        path = _safe_input_file(root / name, f"final closure metadata {name}")
        observed = path.read_bytes()
        if observed != expected:
            raise ClosureError(f"final closure metadata no longer matches verified signed release: {name}")
        result[name] = {
            "name": name,
            "sha256": _sha256_bytes(observed),
            "size": len(observed),
            "path": path,
        }
    return result


def _release_with_metadata(policy: dict[str, Any], base: Path) -> dict[str, Any]:
    global _LAST_METADATA
    release = validate_release_inventory(policy, base)
    if _CONTEXT_METADATA_ROOT is None or _CONTEXT_MODE not in {"sign", "verify"}:
        raise ClosureError("final closure metadata context is not configured")
    if _CONTEXT_MODE == "sign":
        metadata = derive_supply_chain_metadata(release, _CONTEXT_METADATA_ROOT)
    else:
        metadata = verify_supply_chain_metadata(release, _CONTEXT_METADATA_ROOT)
    _LAST_METADATA = metadata
    extended = dict(release)
    extended["artifacts"] = sorted(
        release["artifacts"]
        + [
            {"name": item["name"], "sha256": item["sha256"], "size": item["size"]}
            for item in metadata.values()
        ],
        key=lambda item: item["name"].casefold(),
    )
    extended["sbom"] = {k: metadata[_SBOM_NAME][k] for k in ("name", "sha256", "size")}
    extended["checksums"] = {k: metadata[_CHECKSUMS_NAME][k] for k in ("name", "sha256", "size")}
    extended["signed_release_artifact_count"] = 6
    extended["closure_metadata_count"] = 2
    return extended


def build_closure_statement(**kwargs: Any) -> dict[str, Any]:
    release = kwargs.get("release")
    if not isinstance(release, dict):
        raise ClosureError("release inventory is missing from closure statement")
    statement = _LEGACY_BUILD_CLOSURE_STATEMENT(**kwargs)
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ClosureError("legacy closure predicate construction failed")
    predicate.pop("release_artifact_count", None)
    predicate["signed_release_artifact_count"] = int(release.get("signed_release_artifact_count", 0))
    predicate["closure_metadata_count"] = int(release.get("closure_metadata_count", 0))
    predicate["sbom_provenance"] = "derived-from-verified-signed-release"
    predicate["checksums_provenance"] = "derived-from-verified-signed-release"
    predicate["release_authority_signed_supply_chain_metadata"] = False
    predicate["final_signer_binds_supply_chain_metadata"] = True
    if predicate["signed_release_artifact_count"] != 6 or predicate["closure_metadata_count"] != 2:
        raise ClosureError("final closure supply-chain inventory counts are not exact")
    return statement


def _augment_result(result: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if _LAST_METADATA is None:
        raise ClosureError("final closure supply-chain metadata was not bound")
    enriched = dict(result)
    enriched.update(
        {
            "signed_release_artifact_count": 6,
            "closure_metadata_count": 2,
            "sbom_sha256": _LAST_METADATA[_SBOM_NAME]["sha256"],
            "checksums_sha256": _LAST_METADATA[_CHECKSUMS_NAME]["sha256"],
            "supply_chain_metadata_derived_from_verified_signed_release": True,
            "release_authority_signed_supply_chain_metadata": False,
            "final_signer_binds_supply_chain_metadata": True,
        }
    )
    if output is not None:
        _legacy.atomic_write_json(_safe_output_file(output, "final closure status output"), enriched)
    return enriched


def sign_closure(args: Any) -> dict[str, Any]:
    global _CONTEXT_MODE, _CONTEXT_METADATA_ROOT, _LAST_METADATA
    safe_args = _prepare_sign_args(args)
    _CONTEXT_MODE = "sign"
    _CONTEXT_METADATA_ROOT = safe_args.output_dir
    _LAST_METADATA = None
    result = _legacy.sign_closure(safe_args)
    status_path = safe_args.output_dir / "final-closure-status.json"
    enriched = _augment_result(result, status_path)
    _legacy._scan_output_for_private_keys(safe_args.output_dir)
    return enriched


def verify_closure(args: Any) -> dict[str, Any]:
    global _CONTEXT_MODE, _CONTEXT_METADATA_ROOT, _LAST_METADATA
    safe_args = _prepare_verify_args(args)
    evaluation_parent = safe_args.evaluation.parent
    for path in (safe_args.ga_attestation, safe_args.closure_attestation):
        if path.parent != evaluation_parent:
            raise ClosureError("final closure verification inputs must share one evidence root")
    _CONTEXT_MODE = "verify"
    _CONTEXT_METADATA_ROOT = evaluation_parent
    _LAST_METADATA = None
    result = _legacy.verify_closure(safe_args)
    return _augment_result(result, safe_args.output)


# The preserved implementation keeps all GA evaluation/signature logic. Only its release
# inventory and closure-statement hooks are replaced with the final supply-chain model.
_legacy.validate_release_inventory = _release_with_metadata
_legacy.build_closure_statement = build_closure_statement


def main() -> int:
    args = _legacy.parse_args()
    result = sign_closure(args) if args.command == "sign" else verify_closure(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosureError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"final GA closure failed: {exc}")
