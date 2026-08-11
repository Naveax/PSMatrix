from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_protected_final_release_bundle.py"
spec = importlib.util.spec_from_file_location("protected_release", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def build(root: Path):
    bundle = root / "bundle"
    bundle.mkdir()
    public = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
    (bundle / "psmatrix-2.0.0-release-public.pem").write_bytes(public)
    artifacts = []
    names = ["psmatrix-2.0.0-py3-none-any.whl", "psmatrix-2.0.0-source.tar.gz", "psmatrix-2.0.0-source.zip", "psmatrix-2.0.0-windows-certification-kit.zip", "psmatrix-2.0.0-windows-provisioning-kit.zip", "psmatrix-2.0.0-windows-workers.zip"]
    for index, name in enumerate(names):
        data = f"artifact-{index}\n".encode()
        (bundle / name).write_bytes(data)
        artifacts.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    lock = {"schema": 1, "kind": "psmatrix.windows-authority-final-release-staging-lock", "version": "2.0.0", "promotion_state": "READY_FOR_EXACT_REPOSITORY_COMMIT", "release_commit": "f" * 40, "release_public_key": {"sha256": hashlib.sha256(public).hexdigest()}, "artifacts": artifacts}
    lock_path = root / "final-release-lock.json"
    write_json(lock_path, lock)
    write_json(bundle / "psmatrix-2.0.0-release.json", {"schema": 1})
    write_json(bundle / "psmatrix-2.0.0-release-verification.json", {"valid": True})
    status = {"schema": 1, "kind": "psmatrix.windows-authority-final-protected-release-signing-status", "version": "2.0.0", "status": "PASS", "release_commit": lock["release_commit"], "release_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(), "locked_artifacts": artifacts, "release_private_key_matches_locked_authority": True, "signed_release_manifest_verified": True, "release_artifacts_signed": True, "authority_continuity_from_rc4_verified": True, "release_authority_rotated_during_final_signing": False, "private_key_copied_to_output": False, "rc4_evidence_relabelled_as_final": False, "final_windows_evidence_rebound": False, "final_ga_evaluator_invoked": False, "authoritative": False, "ga_eligible": False}
    write_json(bundle / "psmatrix-2.0.0-protected-release-signing-status.json", status)
    run = {"schema": 1, "kind": "psmatrix.final-release-signing-run-api-verification", "version": "2.0.0", "status": "PASS", "signed_release_run_verified": True, "run_id": 7, "execution_head": "a" * 40}
    return bundle, lock_path, run, names


class ProtectedFinalReleaseBundleVerifierTests(unittest.TestCase):
    def test_exact_locked_bundle_passes_independent_manifest_verification(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-protected-release-") as temporary:
            bundle, lock_path, run, names = build(Path(temporary))
            with patch.object(module, "verify_release_manifest", return_value={"valid": True, "version": "2.0.0", "artifacts": names}):
                value = module.verify(bundle, lock_path, run)
            self.assertEqual(value["verified_artifact_count"], 6)
            self.assertTrue(value["artifact_content_verified"])
            self.assertFalse(value["ga_eligible"])

    def test_locked_artifact_byte_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-protected-release-") as temporary:
            bundle, lock_path, run, names = build(Path(temporary))
            (bundle / names[0]).write_bytes(b"drift\n")
            with self.assertRaises(module.ProtectedReleaseBundleError):
                module.verify(bundle, lock_path, run)

    def test_unverified_signing_run_cannot_promote_bundle(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-protected-release-") as temporary:
            bundle, lock_path, run, names = build(Path(temporary))
            run["status"] = "FAIL"
            with self.assertRaises(module.ProtectedReleaseBundleError):
                module.verify(bundle, lock_path, run)


if __name__ == "__main__":
    unittest.main()
