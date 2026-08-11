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


def evidence(head=HEAD):
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": head, "verified_gate_count": 11, "ready_for_final_ga_evaluator_dispatch": True}


def run():
    return {"id": 77, "name": module.WORKFLOW, "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_sha": HEAD}


class FinalGAEvaluatorRunAPIVerifierTests(unittest.TestCase):
    def test_successful_evaluator_with_attestation_artifact_passes_provenance(self):
        value = module.verify(77, HEAD, evidence(), run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])
        self.assertTrue(value["final_ga_evaluator_run_verified"])
        self.assertTrue(value["ga_root_signing_run_completed"])
        self.assertFalse(value["final_attestation_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_evidence_head_drift_blocks_evaluator(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, evidence("b" * 40), run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])

    def test_missing_or_expired_final_attestation_fails_closed(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, evidence(), run(), [{"id": 88, "name": module.ARTIFACT, "expired": True}])


if __name__ == "__main__":
    unittest.main()
