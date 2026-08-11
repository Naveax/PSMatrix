from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_evaluator_run.py"
spec = importlib.util.spec_from_file_location("evaluator_run", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def content_closure(head=HEAD):
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": head,
        "required_gate_count": 11,
        "api_verified_gate_count": 11,
        "content_verified_gate_count": 11,
        "gates": [{"gate": f"gate-{index}"} for index in range(11)],
        "all_api_artifact_origins_verified": True,
        "all_materialized_trees_verified": True,
        "all_repository_owned_semantic_verifiers_passed": True,
        "all_gate_contents_verified": True,
        "public_auth_cross_gate_semantics_verified": True,
        "all_runs_distinct": True,
        "all_artifacts_distinct": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_root_private_key_read": False,
        "ga_eligible": False,
    }


def run():
    return {"id": 77, "name": module.WORKFLOW, "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_sha": HEAD}


class FinalGAEvaluatorRunAPIVerifierTests(unittest.TestCase):
    def test_successful_evaluator_requires_content_closed_eleven_gate_set(self):
        value = module.verify(77, HEAD, content_closure(), run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])
        self.assertEqual(value["content_verified_gate_count_before_dispatch"], 11)
        self.assertTrue(value["content_closure_required"])
        self.assertTrue(value["final_ga_evaluator_run_verified"])
        self.assertTrue(value["ga_root_signing_run_completed"])
        self.assertFalse(value["final_attestation_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_content_closure_head_drift_blocks_evaluator(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, content_closure("b" * 40), run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])

    def test_old_api_only_receipt_is_no_longer_accepted(self):
        old = {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "verified_gate_count": 11, "ready_for_final_ga_evaluator_dispatch": True}
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, old, run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])

    def test_missing_or_expired_final_attestation_fails_closed(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, content_closure(), run(), [{"id": 88, "name": module.ARTIFACT, "expired": True}])


if __name__ == "__main__":
    unittest.main()
