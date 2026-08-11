from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_lock_repository_content.py"
spec = importlib.util.spec_from_file_location("lock_content", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PUBLIC = b"test-reviewed-public-key\n"
PUBLIC_SHA = hashlib.sha256(PUBLIC).hexdigest()
DRAFT_SHA = "d" * 64
COMMIT = "c" * 40
FINAL = "f" * 40


def contract():
    return {"schema": 1, "kind": "psmatrix.windows-authority-final-release-lock-signing-control-contract", "version": "2.0.0", "final_release_commit": FINAL, "repository_targets": {"lock": "ga-packs/03-authoritative-windows/final-release-lock.json", "public_key": "release-assets/2.0.0/psmatrix-2.0.0-release-public.pem"}}


def ledger():
    return {"schema": 1, "kind": "psmatrix.final-release-lock-input-ledger", "version": "2.0.0", "final_candidate_commit": FINAL, "review_run_id": 3, "promotion_run_id": 4, "reviewed_draft_sha256": DRAFT_SHA, "reviewed_public_key_sha256": PUBLIC_SHA, "lock_control_repository_commit": COMMIT}


def lock():
    return {"schema": 1, "kind": "psmatrix.windows-authority-final-release-staging-lock", "version": "2.0.0", "release_commit": FINAL, "promotion_state": "READY_FOR_EXACT_REPOSITORY_COMMIT", "promotion_evidence": {"human_review_bound": True, "repository_commit_required": True, "reviewed_draft_sha256": DRAFT_SHA, "reviewed_public_key_sha256": PUBLIC_SHA, "review_run_id": "3", "promotion_run_id": "4"}, "release_public_key": {"path": "release-assets/2.0.0/psmatrix-2.0.0-release-public.pem", "sha256": PUBLIC_SHA, "key_id": "release-key"}, "authority_continuity": {"public_key_sha256": PUBLIC_SHA, "key_id": "release-key"}, "release_artifacts_signed": False, "final_windows_evidence_rebound": False, "final_ga_evaluator_invoked": False, "authoritative": False, "ga_eligible": False}


class FinalLockRepositoryContentVerifierTests(unittest.TestCase):
    def test_reviewed_content_binding_passes(self):
        value = module.verify(ledger(), contract(), lock(), PUBLIC)
        self.assertTrue(value["repository_target_content_verified"])
        self.assertFalse(value["release_signing_executed"])

    def test_public_key_byte_drift_fails_closed(self):
        with self.assertRaises(module.FinalLockContentError):
            module.verify(ledger(), contract(), lock(), b"different\n")

    def test_promotion_review_digest_drift_fails_closed(self):
        changed = lock()
        changed["promotion_evidence"]["reviewed_draft_sha256"] = "e" * 64
        with self.assertRaises(module.FinalLockContentError):
            module.verify(ledger(), contract(), changed, PUBLIC)


if __name__ == "__main__":
    unittest.main()
