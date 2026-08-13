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
    return {"schema": 1, "kind": "psmatrix.production-readiness-summary-verification", "version": "2.0.0", "status": "PASS", "repository": module.EXPECTED_REPOSITORY, "verified_environment_count": 12, "verified_check_count": 41, "summary_content_verified": True, "production_readiness_verified": True, "ga_eligible": False}


def lock():
    return {"schema": 1, "kind": "psmatrix.final-release-lock-repository-content-verification", "version": "2.0.0", "status": "PASS", "repository_target_content_verified": True, "release_signing_executed": False, "ga_eligible": False}


def content_closure():
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-content-closure", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "api_verified_gate_count": 11, "content_verified_gate_count": 11, "all_gate_contents_verified": True, "ready_for_final_ga_evaluator_dispatch": True, "ga_eligible": False}


def evaluator():
    return {"schema": 1, "kind": "psmatrix.final-ga-evaluator-run-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "content_verified_gate_count_before_dispatch": 11, "content_closure_required": True, "final_ga_evaluator_run_verified": True, "ga_root_signing_run_completed": True, "final_attestation_content_verified": False, "ga_eligible": False}


def attestation():
    return {"schema": 1, "kind": "psmatrix.final-ga-attestation-bundle-verification", "version": "2.0.0", "status": "PASS", "execution_control_head": HEAD, "required_gate_count": 11, "provenance_run_count": 11, "dsse_cryptographically_verified": True, "root_release_authorities_independent": True, "final_ga_attestation_verified": True, "ga_eligible": True}


class ReleaseClosureReadinessTests(unittest.TestCase):
    def test_full_verified_ga_proof_only_marks_release_ready_not_closed(self):
        value = module.build(readiness(), lock(), content_closure(), evaluator(), attestation())
        self.assertEqual(value["status"], "READY_FOR_RELEASE_CLOSURE")
        self.assertEqual(value["repository"], module.EXPECTED_REPOSITORY)
        self.assertTrue(value["production_readiness_verified"])
        self.assertEqual(value["content_verified_gate_count"], 11)
        self.assertTrue(value["final_ga_attestation_verified"])
        self.assertTrue(value["ga_eligible"])
        self.assertFalse(value["release_closed"])
        self.assertFalse(value["release_tag_created"])
        self.assertFalse(value["final_repo_secret_scan_completed"])

    def test_readiness_repository_identity_is_required(self):
        for repository in (None, "someone-else/PSMatrix"):
            with self.subTest(repository=repository):
                value = readiness()
                if repository is None:
                    value.pop("repository")
                else:
                    value["repository"] = repository
                with self.assertRaises(module.ReleaseClosureReadinessError):
                    module.build(value, lock(), content_closure(), evaluator(), attestation())

    def test_raw_unverified_readiness_is_no_longer_accepted(self):
        raw = {"schema": 1, "kind": "psmatrix.production-readiness-summary", "version": "2.0.0", "status": "PASS", "environment_passed": 12}
        with self.assertRaises(module.ReleaseClosureReadinessError):
            module.build(raw, lock(), content_closure(), evaluator(), attestation())

    def test_api_only_evidence_is_no_longer_accepted(self):
        api_only = {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "verified_gate_count": 11}
        with self.assertRaises(module.ReleaseClosureReadinessError):
            module.build(readiness(), lock(), api_only, evaluator(), attestation())

    def test_execution_head_drift_blocks_release_closure(self):
        broken = evaluator()
        broken["execution_head"] = "b" * 40
        with self.assertRaises(module.ReleaseClosureReadinessError):
            module.build(readiness(), lock(), content_closure(), broken, attestation())

    def test_source_preserves_repository_authority(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn('readiness.get("repository") == EXPECTED_REPOSITORY', text)
        self.assertIn('"repository": EXPECTED_REPOSITORY', text)


if __name__ == "__main__":
    unittest.main()
