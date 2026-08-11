from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_disaster_recovery_bundle.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-disaster-recovery-evidence-producer-contract.json"
spec = importlib.util.spec_from_file_location("recovery_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class DisasterRecoveryBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _bundle(self, root: Path):
        ids = [item["id"] for item in module.list_recovery_cases()]
        report = {"schema": 1, "kind": "psmatrix.recovery-campaign", "tool_version": "2.0.0", "status": "PASS", "cases": [{"id": case_id, "status": "PASS"} for case_id in ids], "summary": {"total": 10, "passed": 10, "failed": 0}}
        report["report_sha256"] = hashlib.sha256(module.canonical_json_bytes(report)).hexdigest()
        write_json(root / "recovery-report.json", report)
        write_json(root / "recovery.dsse.json", {"placeholder": True})
        (root / "recovery-public.pem").write_text("-----BEGIN PUBLIC KEY-----\nrecovery\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        return report

    def test_exact_ten_case_recovery_bundle_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-recovery-bundle-") as temporary:
            root = Path(temporary)
            report = self._bundle(root)
            with patch.object(module, "verify_recovery_report", return_value={"valid": True, "report": report, "key_ids": ["recovery-key"]}), patch.object(module, "public_key_id", return_value="recovery-key"):
                status = {"schema": 1, "kind": "psmatrix.final-disaster-recovery-producer-status", "status": "PASS", "version": "2.0.0", "cases": 10, "report_sha256": report["report_sha256"], "attestation_sha256": module.sha256_file(root / "recovery.dsse.json"), "recovery_key_id": "recovery-key", "recovery_public_key_sha256": module.sha256_file(root / "recovery-public.pem"), "proof_verified": True, "production_state_mutated": False, "recovery_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
                write_json(root / "disaster-recovery-producer-status.json", status)
                value = module.verify(root, self.contract)
            self.assertEqual(value["case_count"], 10)
            self.assertEqual(value["passed_case_count"], 10)
            self.assertTrue(value["report_self_digest_verified"])
            self.assertFalse(value["production_state_mutated"])

    def test_failed_case_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-recovery-bundle-") as temporary:
            root = Path(temporary)
            report = self._bundle(root)
            report["cases"][0]["status"] = "FAIL"
            write_json(root / "recovery-report.json", report)
            with self.assertRaises(module.DisasterRecoveryBundleError):
                module.verify(root, self.contract)

    def test_wrong_signing_authority_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-recovery-bundle-") as temporary:
            root = Path(temporary)
            report = self._bundle(root)
            write_json(root / "disaster-recovery-producer-status.json", {"schema": 1})
            with patch.object(module, "verify_recovery_report", return_value={"valid": True, "report": report, "key_ids": ["wrong-key"]}), patch.object(module, "public_key_id", return_value="recovery-key"):
                with self.assertRaises(module.DisasterRecoveryBundleError):
                    module.verify(root, self.contract)


if __name__ == "__main__":
    unittest.main()
