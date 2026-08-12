from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_validation_evidence_chain_plan.py"
PACK = ROOT / "ga-packs" / "03-authoritative-windows"
READINESS_CONTRACT = PACK / "final-production-readiness-contract.json"
EVALUATOR_CONTRACT = PACK / "final-ga-evaluator-control-contract.json"
BOOTSTRAP_CONTRACT = PACK / "final-production-bootstrap-contract.json"
LOCK_CONTRACT = PACK / "final-release-lock-signing-control-contract.json"

spec = importlib.util.spec_from_file_location("final_validation_evidence_chain_plan", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationEvidenceChainPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.readiness = json.loads(READINESS_CONTRACT.read_text(encoding="utf-8"))
        self.evaluator = json.loads(EVALUATOR_CONTRACT.read_text(encoding="utf-8"))
        self.bootstrap = json.loads(BOOTSTRAP_CONTRACT.read_text(encoding="utf-8"))
        self.lock = json.loads(LOCK_CONTRACT.read_text(encoding="utf-8"))

    def _summary(self, *, ready: bool) -> dict:
        rows = []
        failed = []
        for environment in self.readiness["environments"]:
            missing = []
            missing_paths = []
            if not ready:
                missing.extend(f"secret:{name}" for name in environment.get("required_secrets", []))
                missing.extend(f"var:{name}" for name in environment.get("required_vars", []))
                missing_paths.extend(environment.get("path_vars", []))
            status = "PASS" if not missing and not missing_paths else "FAIL"
            if status == "FAIL":
                failed.append(environment["name"])
            rows.append(
                {
                    "environment": environment["name"],
                    "status": status,
                    "required_checks": len(environment.get("required_secrets", []))
                    + len(environment.get("required_vars", [])),
                    "missing": missing,
                    "missing_paths": missing_paths,
                }
            )
        passed = sum(row["status"] == "PASS" for row in rows)
        return {
            "schema": 1,
            "kind": "psmatrix.production-readiness-summary",
            "version": "2.0.0",
            "status": "PASS" if passed == 12 else "FAIL",
            "producer_source_anchor": self.readiness["producer_source_anchor"],
            "final_release_commit": self.readiness["final_release_commit"],
            "producer_source_coverage": 11,
            "environment_count": 12,
            "environment_passed": passed,
            "environment_failed": 12 - passed,
            "failed_environments": failed,
            "environments": rows,
            "secret_values_observed": False,
            "secret_hashes_observed": False,
            "secret_lengths_observed": False,
            "environment_readiness": passed == 12,
            "production_evidence_runs_complete": False,
            "production_evaluator_ready": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }

    def _build(
        self,
        summary: dict,
        *,
        bootstrap: dict | None = None,
        lock: dict | None = None,
        control_head: str | None = None,
    ) -> dict:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "readiness": root / "readiness.json",
                "evaluator": root / "evaluator.json",
                "bootstrap": root / "bootstrap.json",
                "lock": root / "lock.json",
                "summary": root / "summary.json",
            }
            paths["readiness"].write_text(json.dumps(self.readiness), encoding="utf-8")
            paths["evaluator"].write_text(json.dumps(self.evaluator), encoding="utf-8")
            paths["bootstrap"].write_text(json.dumps(bootstrap or self.bootstrap), encoding="utf-8")
            paths["lock"].write_text(json.dumps(lock or self.lock), encoding="utf-8")
            paths["summary"].write_text(json.dumps(summary), encoding="utf-8")
            return module.build_plan(
                readiness_contract_path=paths["readiness"],
                evaluator_contract_path=paths["evaluator"],
                bootstrap_contract_path=paths["bootstrap"],
                lock_contract_path=paths["lock"],
                readiness_summary_path=paths["summary"],
                control_head=control_head or module.EXPECTED_EXECUTION_ANCHOR,
            )

    def test_all_missing_material_is_blocked_with_truthful_41_plus_path_accounting(self) -> None:
        value = self._build(self._summary(ready=False))
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_MATERIAL")
        self.assertEqual(value["required_check_count"], 41)
        self.assertEqual(value["missing_material_check_count"], 41)
        self.assertEqual(value["missing_path_check_count"], 2)
        self.assertEqual(value["missing_requirement_count"], 43)
        self.assertEqual(value["environment_passed"], 0)
        self.assertFalse(value["ready_for_final_lock_bootstrap"])
        self.assertFalse(value["ready_for_final_release_signing"])
        self.assertFalse(value["ga_eligible"])

    def test_ready_summary_advances_only_to_final_lock_bootstrap(self) -> None:
        value = self._build(self._summary(ready=True))
        self.assertEqual(value["current_stage"], "READY_FOR_FINAL_LOCK_BOOTSTRAP")
        self.assertTrue(value["ready_for_final_lock_bootstrap"])
        self.assertFalse(value["ready_for_final_release_signing"])
        self.assertEqual(len(value["post_readiness_lock_bootstrap"]), 8)
        self.assertTrue(
            value["protected_final_release_signing"]["requires_final_lock_api_verification"]
        )
        self.assertTrue(
            value["protected_final_release_signing"]["requires_final_lock_repository_content_verification"]
        )
        self.assertFalse(value["ga_eligible"])

    def test_execution_head_is_frozen_publication_anchor_not_mutable_main(self) -> None:
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(self._summary(ready=False), control_head="f" * 40)

    def test_bootstrap_insertion_point_cannot_skip_lock_bootstrap(self) -> None:
        bootstrap = copy.deepcopy(self.bootstrap)
        bootstrap["execution_insertion_point"] = {
            "after_stage": "readiness",
            "before_stage": "validation-summary",
        }
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(self._summary(ready=True), bootstrap=bootstrap)

    def test_final_lock_sign_without_exact_match_may_not_be_enabled(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["safety"]["sign_without_exact_lock_match_allowed"] = True
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(self._summary(ready=True), lock=lock)

    def test_evaluator_gate_set_remains_exact_11(self) -> None:
        value = self._build(self._summary(ready=False))
        self.assertEqual(value["evaluator_gate_count"], 11)
        self.assertEqual(set(value["evaluator_gates"]), module.EXPECTED_EVALUATOR_GATES)
        self.assertEqual(len(value["evidence_operations"]), 11)
        self.assertTrue(value["all_evidence_must_share_execution_control_head"])

    def test_secret_observation_or_premature_ga_state_is_rejected(self) -> None:
        for field in (
            "secret_values_observed",
            "secret_hashes_observed",
            "secret_lengths_observed",
            "production_evidence_runs_complete",
            "production_evaluator_ready",
            "final_ga_evaluator_invoked",
            "ga_eligible",
        ):
            with self.subTest(field=field):
                summary = self._summary(ready=False)
                summary[field] = True
                with self.assertRaises(module.FinalValidationEvidenceChainError):
                    self._build(summary)


if __name__ == "__main__":
    unittest.main()
