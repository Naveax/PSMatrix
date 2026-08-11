from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_security_review_bundle.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-security-vulnerability-evidence-producer-contract.json"
spec = importlib.util.spec_from_file_location("security_review_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class SecurityReviewBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _bundle(self, root: Path):
        cfg = self.contract["security_review"]
        report = {"reviewer": "independent", "status": "PASS"}
        write_json(root / cfg["report"], report)
        report_sha = module.sha256_file(root / cfg["report"])
        assertions = {"independent_review": True, "reviewed_commit": module.FINAL_COMMIT, "review_report_sha256": report_sha, "findings": {"critical": 0, "high": 0}, "reviewer": {"conflict_of_interest": False, "key_controlled_by_reviewer": True}}
        result = {"assertions": assertions}
        write_json(root / cfg["result"], result)
        write_json(root / cfg["attestation"], {"placeholder": True})
        (root / cfg["public_key"]).write_text("-----BEGIN PUBLIC KEY-----\nreview\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        write_json(root / "security-review-submission-validation.json", {"status": "PASS", "independent_review": True, "critical_high_blockers_absent": True, "reviewer": {"conflict_of_interest": False, "key_controlled_by_reviewer": True}})
        (root / self.contract["security_review_packet"]["packet"]).write_bytes(b"packet\n")
        release_public = root / "release-public.pem"
        release_public.write_text("-----BEGIN PUBLIC KEY-----\nrelease\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        status = {"schema": 1, "kind": "psmatrix.final-security-review-producer-status", "status": "PASS", "version": "2.0.0", "reviewed_commit": module.FINAL_COMMIT, "review_report_sha256": report_sha, "security_review_key_id": "review-key", "security_review_public_key_sha256": module.sha256_file(root / cfg["public_key"]), "proof_verified": True, "independent_review_attested": True, "reviewer_key_control_attested": True, "critical_high_blockers_absent": True, "security_review_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
        write_json(root / "security-review-producer-status.json", status)
        return release_public, result

    def test_completed_independent_review_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-security-review-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            def fake_key_id(path):
                return "release-key" if Path(path).name == "release-public.pem" else "review-key"
            with patch.object(module, "verify_ga_proof", return_value={"valid": True, "result": result}), patch.object(module, "public_key_id", side_effect=fake_key_id):
                value = module.verify(root, release_public, self.contract)
            self.assertTrue(value["independent_review_verified"])
            self.assertTrue(value["reviewer_key_control_verified"])
            self.assertEqual(value["critical_findings"], 0)
            self.assertFalse(value["ga_eligible"])

    def test_conflict_of_interest_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-security-review-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            validation_path = root / "security-review-submission-validation.json"
            validation = json.loads(validation_path.read_text())
            validation["reviewer"]["conflict_of_interest"] = True
            write_json(validation_path, validation)
            with self.assertRaises(module.SecurityReviewBundleError):
                module.verify(root, release_public, self.contract)

    def test_release_and_review_authority_reuse_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-security-review-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            with patch.object(module, "verify_ga_proof", return_value={"valid": True, "result": result}), patch.object(module, "public_key_id", return_value="same-key"):
                with self.assertRaises(module.SecurityReviewBundleError):
                    module.verify(root, release_public, self.contract)


if __name__ == "__main__":
    unittest.main()
