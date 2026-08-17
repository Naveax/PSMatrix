from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_release_closure_readiness.py"
spec = importlib.util.spec_from_file_location("release_closure", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def readiness():
    return {"schema": 1, "kind": "psmatrix.production-readiness-summary-verification", "version": "2.0.0", "status": "PASS", "repository": module.EXPECTED_REPOSITORY, "run_id": 42, "workflow": module.EXPECTED_READINESS_WORKFLOW, "event": "workflow_dispatch", "exact_head": module.EXPECTED_READINESS_HEAD, "immutable_ref": module.EXPECTED_READINESS_REF, "run_conclusion": "success", "artifact": module.EXPECTED_READINESS_ARTIFACT, "artifact_id": 99, "artifact_nonexpired": True, "verified_environment_count": 12, "verified_check_count": 41, "summary_content_verified": True, "production_readiness_verified": True, "ga_eligible": False}


def lock():
    return {"schema": 1, "kind": "psmatrix.final-release-lock-repository-content-verification", "version": "2.0.0", "status": "PASS", "repository_target_content_verified": True, "release_signing_executed": False, "ga_eligible": False}


def closure():
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-content-closure", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "api_verified_gate_count": 11, "content_verified_gate_count": 11, "all_gate_contents_verified": True, "ready_for_final_ga_evaluator_dispatch": True, "ga_eligible": False}


def closure_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def evaluator(value=None, bound=None):
    value = closure() if value is None else value
    bound = closure_bytes(value) if bound is None else bound
    canonical = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {"schema": 1, "kind": "psmatrix.final-ga-evaluator-run-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "content_verified_gate_count_before_dispatch": 11, "content_closure_required": True, "content_closure_reverification_required": True, "content_closure_file_sha256": hashlib.sha256(bound).hexdigest(), "content_closure_file_size": len(bound), "content_closure_canonical_sha256": canonical, "content_closure_reverification_kind": "psmatrix.final-ga-evidence-content-closure-verification", "content_closure_reverification_file_sha256": hashlib.sha256(b"receipt").hexdigest(), "content_closure_reverification_file_size": 7, "content_closure_repository_owned_rederivation": True, "content_closure_exactly_recomputed": True, "final_ga_evaluator_run_verified": True, "ga_root_signing_run_completed": True, "final_attestation_content_verified": False, "ga_eligible": False}


def attestation():
    return {"schema": 1, "kind": "psmatrix.final-ga-attestation-bundle-verification", "version": "2.0.0", "status": "PASS", "execution_control_head": HEAD, "required_gate_count": 11, "provenance_run_count": 11, "dsse_cryptographically_verified": True, "root_release_authorities_independent": True, "final_ga_attestation_verified": True, "ga_eligible": True}


def live_lock():
    return {"status": "PASS", "self_describing_receipt_provenance_verified": True, "live_repository_authority_verified": True, "repository_target_content_verified": True, "repository_public_key_bytes_verified": True, "release_signing_executed": False, "ga_eligible": False, "historical_input_ledger_execution_reverified": False, "historical_review_execution_reverified": False, "historical_promotion_execution_reverified": False}


def build_value(value=None, verification=None, supplied=None):
    value = closure() if value is None else value
    supplied = closure_bytes(value) if supplied is None else supplied
    return module.build(readiness(), lock(), value, evaluator(value, supplied) if verification is None else verification, attestation(), content_closure_file_sha256=hashlib.sha256(supplied).hexdigest(), content_closure_file_size=len(supplied))


class ReleaseClosureReadinessTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(module, "_verify_final_lock_live_authority", return_value=live_lock())
        p.start()
        self.addCleanup(p.stop)

    def test_ready_receipt_preserves_content_provenance(self):
        value = closure()
        supplied = closure_bytes(value)
        result = build_value(value=value, supplied=supplied)
        self.assertEqual(result["content_closure_file_sha256"], hashlib.sha256(supplied).hexdigest())
        self.assertEqual(result["content_closure_file_size"], len(supplied))
        self.assertTrue(result["content_closure_exactly_recomputed"])
        self.assertFalse(result["release_closed"])

    def test_rejects_raw_byte_drift(self):
        value = closure()
        original = closure_bytes(value)
        different = json.dumps(value, separators=(",", ":")).encode()
        with self.assertRaises(module.ReleaseClosureReadinessError):
            build_value(value=value, verification=evaluator(value, original), supplied=different)

    def test_rejects_canonical_digest_drift(self):
        broken = evaluator()
        broken["content_closure_canonical_sha256"] = hashlib.sha256(b"different").hexdigest()
        with self.assertRaises(module.ReleaseClosureReadinessError):
            build_value(verification=broken)

    def test_rejects_missing_reverification_authority(self):
        broken = evaluator()
        broken["content_closure_repository_owned_rederivation"] = False
        with self.assertRaises(module.ReleaseClosureReadinessError):
            build_value(verification=broken)

    def test_execution_head_drift_blocks_release_closure(self):
        broken = evaluator()
        broken["execution_head"] = "c" * 40
        with self.assertRaises(module.ReleaseClosureReadinessError):
            build_value(verification=broken)


if __name__ == "__main__":
    unittest.main()
