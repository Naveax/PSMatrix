from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_release_closure_readiness.py"
spec = importlib.util.spec_from_file_location("release_closure", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def readiness():
    return {"schema": 1, "kind": "psmatrix.production-readiness-summary", "version": "2.0.0", "status": "PASS", "environment_count": 12, "environment_passed": 12, "environment_failed": 0, "environment_readiness": True}


def lock():
    return {"schema": 1, "kind": "psmatrix.final-release-lock-repository-content-verification", "version": "2.0.0", "status": "PASS", "repository_target_content_verified": True}


def evidence():
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "verified_gate_count": 11, "execution_head": HEAD}


def evaluator():
    return {"schema": 1, "kind": "psmatrix.final-ga-evaluator-run-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "final_ga_evaluator_run_verified": True, "ga_root_signing_run_completed": True}


def attestation():
    return {"schema": 1, "kind": "psmatrix.final-ga-attestation-bundle-verification", "version": "2.0.0", "status": "PASS", "execution_control_head": HEAD, "required_gate_count": 11, "final_ga_attestation_verified": True, "ga_eligible": True}


class ReleaseClosureReadinessTests(unittest.TestCase):
    def test_full_ga_proof_only_marks_release_ready_not_closed(self):
        value = module.build(readiness(), lock(), evidence(), evaluator(), attestation())
        self.assertEqual(value["status"], "READY_FOR_RELEASE_CLOSURE")
        self.assertTrue(value["ga_eligible"])
        self.assertFalse(value["release_closed"])
        self.assertFalse(value["release_tag_created"])
        self.assertFalse(value["final_repo_secret_scan_completed"])

    def test_missing_readiness_blocks_release_closure(self):
        broken = readiness()
        broken["environment_passed"] = 11
        with self.assertRaises(module.ReleaseClosureReadinessError):
            module.build(broken, lock(), evidence(), evaluator(), attestation())

    def test_execution_head_drift_blocks_release_closure(self):
        broken = evaluator()
        broken["execution_head"] = "b" * 40
        with self.assertRaises(module.ReleaseClosureReadinessError):
            module.build(readiness(), lock(), evidence(), broken, attestation())


if __name__ == "__main__":
    unittest.main()
