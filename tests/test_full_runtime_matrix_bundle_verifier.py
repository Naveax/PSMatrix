from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_full_runtime_matrix_bundle.py"
spec = importlib.util.spec_from_file_location("full_matrix_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class FullRuntimeMatrixBundleVerifierTests(unittest.TestCase):
    def _bundle(self, root: Path):
        binding = {"release_version": "2.0.0", "release_commit": module.FINAL_COMMIT}
        report = {"schema": 8, "status": "PASS", "matrix": {"full": True, "require_complete": True, "differential_mode": "strict", "coverage": {"declared": 25, "passed": 25, "incomplete": 0, "failed": 0}}, "targets": [{"id": str(i), "status": "PASS"} for i in range(25)]}
        write_json(root / "full-matrix-report.json", report)
        write_json(root / "full-matrix-report.dsse.json", {"placeholder": True})
        write_json(root / "full-matrix-release-binding.json", binding)
        (root / "ci-public.pem").write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        return report, binding

    def test_exact_twenty_five_target_signed_matrix_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bundle-") as temporary:
            root = Path(temporary)
            _, binding = self._bundle(root)
            with patch.object(module, "validate_canonical_full_matrix_report", return_value={"valid": True}), patch.object(module, "verify_full_matrix_ga_attestation", return_value={"valid": True, "targets": 25, "release_binding": binding}), patch.object(module, "public_key_id", return_value="ci-key"):
                status = {"schema": 1, "kind": "psmatrix.final-full-runtime-matrix-producer-status", "status": "PASS", "version": "2.0.0", "targets": 25, "passed": 25, "release_bound": True, "report_sha256": module.sha256_file(root / "full-matrix-report.json"), "attestation_sha256": module.sha256_file(root / "full-matrix-report.dsse.json"), "ci_public_key_sha256": module.sha256_file(root / "ci-public.pem"), "ci_key_id": "ci-key", "attestation_verified": True, "ci_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
                write_json(root / "full-matrix-producer-status.json", status)
                value = module.verify(root)
            self.assertEqual(value["canonical_target_count"], 25)
            self.assertEqual(value["passed_target_count"], 25)
            self.assertTrue(value["release_bound"])
            self.assertFalse(value["ga_eligible"])

    def test_twenty_four_passes_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bundle-") as temporary:
            root = Path(temporary)
            report, _ = self._bundle(root)
            report["matrix"]["coverage"]["passed"] = 24
            write_json(root / "full-matrix-report.json", report)
            with self.assertRaises(module.FullRuntimeMatrixBundleError):
                module.verify(root)

    def test_unsigned_or_invalid_attestation_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bundle-") as temporary:
            root = Path(temporary)
            self._bundle(root)
            write_json(root / "full-matrix-producer-status.json", {"schema": 1})
            with patch.object(module, "validate_canonical_full_matrix_report", return_value={"valid": True}), patch.object(module, "verify_full_matrix_ga_attestation", return_value={"valid": False}):
                with self.assertRaises(module.FullRuntimeMatrixBundleError):
                    module.verify(root)


if __name__ == "__main__":
    unittest.main()
