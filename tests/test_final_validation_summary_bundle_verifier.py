from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_validation_summary_bundle.py"
spec = importlib.util.spec_from_file_location("validation_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class FinalValidationSummaryBundleVerifierTests(unittest.TestCase):
    def _bundle(self, root: Path):
        summary = {"kind": "psmatrix.validation-summary", "status": "PASS", "version": "2.0.0", "git_commit": module.FINAL_COMMIT, "automated_tests": {"passed": 12, "failed": 0, "skipped": 0, "total": 12}, "reproducibility": {"source_zip": True, "source_tar_gz": True, "wheel": True}, "offline_install_exit_code": 0, "core_release_signature_valid": True, "distribution_signature_valid": True}
        write_json(root / "validation-summary.json", summary)
        write_json(root / "validation-summary.dsse.json", {"placeholder": True})
        (root / "ci-public.pem").write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        return summary

    def test_exact_validation_bundle_passes_independent_attestation(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-validation-bundle-") as temporary:
            root = Path(temporary)
            self._bundle(root)
            with patch.object(module, "verify_ga_artifact_attestation", return_value={"valid": True}), patch.object(module, "public_key_id", return_value="ci-key"):
                status = {"schema": 1, "kind": "psmatrix.final-validation-summary-producer-status", "status": "PASS", "version": "2.0.0", "validation_summary_sha256": module.sha256_file(root / "validation-summary.json"), "attestation_sha256": module.sha256_file(root / "validation-summary.dsse.json"), "ci_public_key_sha256": module.sha256_file(root / "ci-public.pem"), "ci_key_id": "ci-key", "attestation_verified": True, "ci_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
                write_json(root / "validation-producer-status.json", status)
                value = module.verify(root)
            self.assertEqual(value["automated_tests_total"], 12)
            self.assertTrue(value["attestation_cryptographically_verified"])
            self.assertFalse(value["ga_eligible"])

    def test_test_failure_accounting_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-validation-bundle-") as temporary:
            root = Path(temporary)
            summary = self._bundle(root)
            summary["automated_tests"]["failed"] = 1
            write_json(root / "validation-summary.json", summary)
            with self.assertRaises(module.ValidationSummaryBundleError):
                module.verify(root)

    def test_invalid_dsse_blocks_bundle(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-validation-bundle-") as temporary:
            root = Path(temporary)
            self._bundle(root)
            write_json(root / "validation-producer-status.json", {"schema": 1})
            with patch.object(module, "verify_ga_artifact_attestation", return_value={"valid": False}):
                with self.assertRaises(module.ValidationSummaryBundleError):
                    module.verify(root)


if __name__ == "__main__":
    unittest.main()
