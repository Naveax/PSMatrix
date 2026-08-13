from __future__ import annotations

import hashlib
import importlib.util
import json
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


def verified_inputs(closure):
    raw = (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8")
    raw_sha = hashlib.sha256(raw).hexdigest()
    canonical_sha = hashlib.sha256(
        json.dumps(closure, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    verification = {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": closure.get("execution_head"),
        "single_binding_count": 9,
        "public_auth_binding_count": 1,
        "source_binding_receipt_count": 10,
        "verified_gate_count": 11,
        "closure_canonical_sha256": canonical_sha,
        "repository_owned_rederivation": True,
        "closure_exactly_recomputed": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "content_closure_file_sha256": raw_sha,
    }
    verification_raw = (json.dumps(verification, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return verification, raw_sha, len(raw), hashlib.sha256(verification_raw).hexdigest(), len(verification_raw)


def verify_value(closure, artifacts):
    verification, raw_sha, raw_size, verification_sha, verification_size = verified_inputs(closure)
    return module.verify(77, HEAD, closure, verification, raw_sha, raw_size, verification_sha, verification_size, run(), artifacts)


class FinalGAEvaluatorRunAPIVerifierTests(unittest.TestCase):
    def test_successful_evaluator_requires_reverified_content_closed_eleven_gate_set(self):
        value = verify_value(content_closure(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])
        self.assertEqual(value["content_verified_gate_count_before_dispatch"], 11)
        self.assertTrue(value["content_closure_required"])
        self.assertTrue(value["content_closure_reverification_required"])
        self.assertTrue(value["content_closure_repository_owned_rederivation"])
        self.assertTrue(value["content_closure_exactly_recomputed"])
        self.assertTrue(value["final_ga_evaluator_run_verified"])
        self.assertTrue(value["ga_root_signing_run_completed"])
        self.assertFalse(value["final_attestation_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_content_closure_head_drift_blocks_evaluator(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            verify_value(content_closure("b" * 40), [{"id": 88, "name": module.ARTIFACT, "expired": False}])

    def test_old_api_only_receipt_is_no_longer_accepted(self):
        old = {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "verified_gate_count": 11, "ready_for_final_ga_evaluator_dispatch": True}
        verification, raw_sha, raw_size, verification_sha, verification_size = verified_inputs(content_closure())
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            module.verify(77, HEAD, old, verification, raw_sha, raw_size, verification_sha, verification_size, run(), [{"id": 88, "name": module.ARTIFACT, "expired": False}])

    def test_missing_or_expired_final_attestation_fails_closed(self):
        with self.assertRaises(module.FinalGAEvaluatorRunError):
            verify_value(content_closure(), [{"id": 88, "name": module.ARTIFACT, "expired": True}])


if __name__ == "__main__":
    unittest.main()
