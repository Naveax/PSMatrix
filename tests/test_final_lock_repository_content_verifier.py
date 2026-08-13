from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_lock_repository_content.py"
LIVE_SCRIPT = ROOT / "scripts" / "ga" / "verify_final_lock_live_repository_authority.py"
spec = importlib.util.spec_from_file_location("lock_content", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
live_spec = importlib.util.spec_from_file_location("lock_live", LIVE_SCRIPT)
assert live_spec and live_spec.loader
live = importlib.util.module_from_spec(live_spec)
live_spec.loader.exec_module(live)

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

    def test_receipt_exposes_exact_live_repository_provenance(self):
        value = module.verify(ledger(), contract(), lock(), PUBLIC)
        self.assertEqual(value["repository_commit"], COMMIT)
        self.assertEqual(value["lock_control_repository_commit"], COMMIT)
        self.assertEqual(value["final_candidate_commit"], FINAL)
        self.assertEqual(value["review_run_id"], 3)
        self.assertEqual(value["promotion_run_id"], 4)
        self.assertEqual(value["reviewed_draft_sha256"], DRAFT_SHA)
        self.assertEqual(value["reviewed_public_key_sha256"], PUBLIC_SHA)

    def test_non_positive_review_run_id_fails_closed(self):
        changed = ledger()
        changed["review_run_id"] = 0
        with self.assertRaises(module.FinalLockContentError):
            module.verify(changed, contract(), lock(), PUBLIC)

    def test_live_helper_reconstructs_minimal_ledger_from_canonical_receipt(self):
        receipt = module.verify(ledger(), contract(), lock(), PUBLIC)
        expected = {
            "schema": 1,
            "kind": "psmatrix.final-release-lock-live-repository-authority-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository_commit": COMMIT,
            "final_release_commit": FINAL,
            "repository_public_key_bytes_verified": True,
            "repository_target_content_verified": True,
            "release_signing_executed": False,
            "ga_eligible": False,
            "historical_input_ledger_execution_reverified": False,
            "historical_review_execution_reverified": False,
            "historical_promotion_execution_reverified": False,
            "live_repository_authority_verified": True,
        }
        with patch.object(live, "_verify_repository_content", return_value=expected) as verify_content:
            value = live.verify_receipt_live_authority(receipt, contract())
        reconstructed = verify_content.call_args.args[0]
        self.assertEqual(reconstructed["lock_control_repository_commit"], COMMIT)
        self.assertEqual(reconstructed["review_run_id"], 3)
        self.assertEqual(reconstructed["promotion_run_id"], 4)
        self.assertEqual(reconstructed["reviewed_draft_sha256"], DRAFT_SHA)
        self.assertEqual(reconstructed["reviewed_public_key_sha256"], PUBLIC_SHA)
        self.assertTrue(value["self_describing_receipt_provenance_verified"])
        self.assertFalse(value["historical_review_execution_reverified"])
        self.assertFalse(value["historical_promotion_execution_reverified"])


if __name__ == "__main__":
    unittest.main()
