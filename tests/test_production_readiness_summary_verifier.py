from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_readiness_summary.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
spec = importlib.util.spec_from_file_location("readiness_summary", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductionReadinessSummaryVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.run = {"schema": 1, "kind": "psmatrix.production-readiness-run-api-verification", "version": "2.0.0", "status": "PASS", "readiness_pass_observed": True, "run_id": 42, "exact_head": "a" * 40}
        rows = []
        for item in self.contract["environments"]:
            required = len(item.get("required_secrets") or []) + len(item.get("required_vars") or [])
            rows.append({"environment": item["name"], "status": "PASS", "required_checks": required, "missing": [], "missing_paths": []})
        self.summary = {"schema": 1, "kind": "psmatrix.production-readiness-summary", "version": "2.0.0", "status": "PASS", "producer_source_anchor": self.contract["producer_source_anchor"], "final_release_commit": self.contract["final_release_commit"], "producer_source_coverage": 11, "environment_count": 12, "environment_passed": 12, "environment_failed": 0, "failed_environments": [], "environments": rows, "secret_values_observed": False, "secret_hashes_observed": False, "secret_lengths_observed": False, "environment_readiness": True, "production_evidence_runs_complete": False, "production_evaluator_ready": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}

    def test_exact_twelve_environment_forty_one_check_pass_is_verified(self):
        value = module.verify(self.summary, self.contract, self.run)
        self.assertEqual(value["verified_environment_count"], 12)
        self.assertEqual(value["verified_check_count"], 41)
        self.assertTrue(value["production_readiness_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_missing_environment_check_fails_closed(self):
        self.summary["environments"][0]["required_checks"] -= 1
        with self.assertRaises(module.ReadinessSummaryVerificationError):
            module.verify(self.summary, self.contract, self.run)

    def test_failed_or_unverified_run_cannot_promote_summary(self):
        self.run["readiness_pass_observed"] = False
        with self.assertRaises(module.ReadinessSummaryVerificationError):
            module.verify(self.summary, self.contract, self.run)


if __name__ == "__main__":
    unittest.main()
