from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "run_final_attestation_content_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_attestation_content_operation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalAttestationContentOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.receipt = {
            "schema": 1,
            "kind": "psmatrix.final-ga-evaluator-run-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 12345,
            "execution_head": "a" * 40,
            "api_verified_gate_count_before_dispatch": 11,
            "content_verified_gate_count_before_dispatch": 11,
            "content_closure_required": True,
            "final_ga_evaluator_run_verified": True,
            "ga_root_signing_run_completed": True,
            "final_attestation_artifact": "psmatrix-2.0.0-final-ga-attestation",
            "final_attestation_artifact_id": 67890,
            "final_attestation_artifact_nonexpired": True,
            "final_attestation_content_verified": False,
            "ga_eligible": False,
        }

    def test_exact_pre_content_run_receipt_is_accepted(self) -> None:
        artifact_id, head = self.module.validate_run_verification(self.receipt)
        self.assertEqual(artifact_id, 67890)
        self.assertEqual(head, "a" * 40)

    def test_pre_dispatch_content_count_must_be_exact_11(self) -> None:
        self.receipt["content_verified_gate_count_before_dispatch"] = 10
        with self.assertRaises(self.module.FinalAttestationContentOperationError):
            self.module.validate_run_verification(self.receipt)

    def test_invalid_evaluator_run_id_fails_closed(self) -> None:
        self.receipt["run_id"] = 0
        with self.assertRaises(self.module.FinalAttestationContentOperationError):
            self.module.validate_run_verification(self.receipt)

    def test_already_ga_eligible_run_receipt_is_rejected(self) -> None:
        self.receipt["final_attestation_content_verified"] = True
        self.receipt["ga_eligible"] = True
        with self.assertRaises(self.module.FinalAttestationContentOperationError):
            self.module.validate_run_verification(self.receipt)

    def test_workspace_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(self.module.FinalAttestationContentOperationError):
            self.module._external_workspace(ROOT / ".tmp-final-attestation")

    def test_source_uses_exact_artifact_id_safe_extract_independent_verifier_and_bounded_errors(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("materialize_verified_evidence_artifact.py", text)
        self.assertIn("verify_final_ga_attestation_bundle.py", text)
        self.assertIn("materializer.download", text)
        self.assertIn("materializer.safe_extract", text)
        self.assertIn("exact final-attestation artifact materialization failed", text)
        self.assertIn("independent final-attestation semantic verification failed", text)
        self.assertIn("semantic_verification_mutated_tree", text)
        self.assertIn("final_ga_attestation_verified", text)
        self.assertIn('"ga_eligible": True', text)
        self.assertNotIn("KeyError, Exception", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
