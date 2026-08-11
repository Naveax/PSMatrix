from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.release import verify_release_manifest

PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)


class ProtectedReleaseBundleError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProtectedReleaseBundleError(f"JSON root must be object: {path.name}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(bundle_root: Path, lock_path: Path, run_verification: dict[str, Any]) -> dict[str, Any]:
    bundle = bundle_root.resolve()
    lock_path = lock_path.resolve()
    if not bundle.is_dir() or not lock_path.is_file():
        raise ProtectedReleaseBundleError("protected release bundle or active lock is missing")
    if run_verification.get("schema") != 1 or run_verification.get("kind") != "psmatrix.final-release-signing-run-api-verification" or run_verification.get("version") != "2.0.0" or run_verification.get("status") != "PASS" or run_verification.get("signed_release_run_verified") is not True:
        raise ProtectedReleaseBundleError("release signing run API verification must PASS")
    lock = _json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-final-release-staging-lock" or lock.get("version") != "2.0.0" or lock.get("promotion_state") != "READY_FOR_EXACT_REPOSITORY_COMMIT":
        raise ProtectedReleaseBundleError("active final release lock identity/state mismatch")
    manifest = bundle / "psmatrix-2.0.0-release.json"
    public = bundle / "psmatrix-2.0.0-release-public.pem"
    recorded = bundle / "psmatrix-2.0.0-release-verification.json"
    status_path = bundle / "psmatrix-2.0.0-protected-release-signing-status.json"
    for path in (manifest, public, recorded, status_path):
        if not path.is_file():
            raise ProtectedReleaseBundleError(f"protected release file is missing: {path.name}")
    for path in bundle.rglob("*"):
        if path.is_file() and any(marker in path.read_bytes() for marker in PRIVATE_MARKERS):
            raise ProtectedReleaseBundleError(f"private-key material found in protected release bundle: {path.name}")
    key = lock.get("release_public_key")
    if not isinstance(key, dict) or key.get("sha256") != _sha(public):
        raise ProtectedReleaseBundleError("protected release public authority differs from active lock")
    status = _json(status_path)
    if status.get("schema") != 1 or status.get("kind") != "psmatrix.windows-authority-final-protected-release-signing-status" or status.get("version") != "2.0.0" or status.get("status") != "PASS":
        raise ProtectedReleaseBundleError("protected release signing status identity mismatch")
    if status.get("release_commit") != lock.get("release_commit") or status.get("release_lock_sha256") != _sha(lock_path):
        raise ProtectedReleaseBundleError("protected release status is not bound to active lock bytes")
    locked = lock.get("artifacts")
    status_locked = status.get("locked_artifacts")
    if not isinstance(locked, list) or len(locked) != 6 or status_locked != locked:
        raise ProtectedReleaseBundleError("protected release locked-artifact metadata mismatch")
    for item in locked:
        if not isinstance(item, dict):
            raise ProtectedReleaseBundleError("locked artifact entry is invalid")
        path = bundle / str(item.get("name") or "")
        if not path.is_file() or path.stat().st_size != item.get("size") or _sha(path) != item.get("sha256"):
            raise ProtectedReleaseBundleError(f"protected release artifact bytes mismatch: {item.get('name')}")
    verification = verify_release_manifest(manifest, bundle, signing_public_key=public)
    if not isinstance(verification, dict) or verification.get("valid") is not True or verification.get("version") != "2.0.0":
        raise ProtectedReleaseBundleError("independent protected release manifest verification failed")
    if set(verification.get("artifacts") or []) != {item["name"] for item in locked}:
        raise ProtectedReleaseBundleError("verified release manifest artifact set differs from lock")
    recorded_verification = _json(recorded)
    if recorded_verification.get("valid") is not True:
        raise ProtectedReleaseBundleError("recorded release verification is not valid")
    for field, expected in (("release_private_key_matches_locked_authority", True), ("signed_release_manifest_verified", True), ("release_artifacts_signed", True), ("authority_continuity_from_rc4_verified", True), ("release_authority_rotated_during_final_signing", False), ("private_key_copied_to_output", False), ("rc4_evidence_relabelled_as_final", False), ("final_windows_evidence_rebound", False), ("final_ga_evaluator_invoked", False), ("authoritative", False), ("ga_eligible", False)):
        if status.get(field) != expected:
            raise ProtectedReleaseBundleError(f"protected release status boundary mismatch: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.protected-final-release-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_verification.get("run_id"),
        "execution_head": run_verification.get("execution_head"),
        "release_commit": lock.get("release_commit"),
        "locked_artifact_count": 6,
        "verified_artifact_count": 6,
        "release_manifest_cryptographically_verified": True,
        "release_public_authority_bound_to_lock": True,
        "artifact_content_verified": True,
        "signed_release_verified": True,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify the downloaded protected final release bundle against the exact active lock")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--active-lock", type=Path, required=True)
    parser.add_argument("--run-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, args.active_lock, json.loads(args.run_verification.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("protected_final_release_bundle_verification=PASS artifacts=6/6")
        print("signed_release_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ProtectedReleaseBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"protected final release bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
