from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_release_signing_run.py"
spec = importlib.util.spec_from_file_location("release_signing", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def lock_verification(status="PASS"):
    return {"schema": 1, "kind": "psmatrix.final-release-lock-repository-content-verification", "version": "2.0.0", "status": status, "repository_target_content_verified": status == "PASS"}


def run():
    return {"id": 7, "name": module.WORKFLOW, "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_sha": HEAD}


class FinalReleaseSigningRunVerifierTests(unittest.TestCase):
    def test_verified_lock_and_successful_signing_run_pass(self):
        value = module.verify(7, HEAD, lock_verification(), run(), [{"id": 8, "name": module.ARTIFACT, "expired": False}])
        self.assertTrue(value["signed_release_run_verified"])
        self.assertFalse(value["artifact_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_unverified_lock_blocks_run_acceptance(self):
        with self.assertRaises(module.ReleaseSigningVerificationError):
            module.verify(7, HEAD, lock_verification("FAIL"), run(), [{"id": 8, "name": module.ARTIFACT, "expired": False}])

    def test_head_or_artifact_drift_fails_closed(self):
        with self.assertRaises(module.ReleaseSigningVerificationError):
            module.verify(7, "b" * 40, lock_verification(), run(), [{"id": 8, "name": module.ARTIFACT, "expired": False}])
        with self.assertRaises(module.ReleaseSigningVerificationError):
            module.verify(7, HEAD, lock_verification(), run(), [])


if __name__ == "__main__":
    unittest.main()
