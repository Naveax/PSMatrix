from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_validation_evidence_chain_plan.py"
READINESS_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
EVALUATOR_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
CONTROL_HEAD = "06c80421ecb8c6668e5e4334f9138a55ae56e1fd"

spec = importlib.util.spec_from_file_location("final_validation_evidence_chain_plan", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationEvidenceChainPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.readiness_contract = json.loads(READINESS_CONTRACT.read_text(encoding="utf-8"))
        self.evaluator_contract = json.loads(EVALUATOR_CONTRACT.read_text(encoding="utf-8"))

    def _summary(self, *, ready: bool) -> dict:
        rows = []
        failed = []
        for environment in self.readiness_contract["environments"]:
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
            "evaluated_at": "2026-08-12T00:00:00Z",
            "producer_source_anchor": self.readiness_contract["producer_source_anchor"],
            "final_release_commit": self.readiness_contract["final_release_commit"],
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

    def _build(self, summary: dict, *, readiness_contract: dict | None = None, evaluator_contract: dict | None = None):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            readiness_path = root / "readiness-contract.json"
            evaluator_path = root / "evaluator-contract.json"
            summary_path = root / "readiness-summary.json"
            readiness_path.write_text(
                json.dumps(readiness_contract or self.readiness_contract), encoding="utf-8"
            )
            evaluator_path.write_text(
                json.dumps(evaluator_contract or self.evaluator_contract), encoding="utf-8"
            )
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            return module.build_plan(
                readiness_contract_path=readiness_path,
                evaluator_contract_path=evaluator_path,
                readiness_summary_path=summary_path,
                control_head=CONTROL_HEAD,
            )

    def test_all_missing_material_is_blocked_without_mutating_ga_state(self) -> None:
        value = self._build(self._summary(ready=False))
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_MATERIAL")
        self.assertEqual(value["required_check_count"], 41)
        self.assertEqual(value["environment_count"], 12)
        self.assertEqual(value["environment_passed"], 0)
        self.assertEqual(value["environment_failed"], 12)
        self.assertEqual(value["evaluator_gate_count"], 11)
        self.assertEqual(len(value["evidence_operations"]), 11)
        self.assertEqual(value["missing_requirement_count"], 43)
        self.assertFalse(value["ready_for_final_release_signing"])
        self.assertFalse(value["production_state_mutated"])
        self.assertFalse(value["final_ga_evaluator_invoked"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_environment_ready_only_advances_to_protected_release_signing(self) -> None:
        value = self._build(self._summary(ready=True))
        self.assertEqual(value["current_stage"], "READY_FOR_FINAL_RELEASE_SIGNING")
        self.assertEqual(value["environment_passed"], 12)
        self.assertEqual(value["missing_requirement_count"], 0)
        self.assertTrue(value["ready_for_final_release_signing"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])
        self.assertEqual(
            value["protected_final_validation"]["workflow_path"],
            ".github/workflows/ga-final-validation-summary.yml",
        )
        self.assertTrue(value["protected_final_validation"]["requires_release_signing_run_id"])

    def test_plan_binds_exact_evaluator_gate_and_artifact_contract(self) -> None:
        value = self._build(self._summary(ready=False))
        operations = {item["gate"]: item for item in value["evidence_operations"]}
        self.assertEqual(set(operations), module.EXPECTED_EVALUATOR_GATES)
        self.assertEqual(
            operations["signed-release"]["artifact"], "psmatrix-2.0.0-protected-release"
        )
        self.assertEqual(
            operations["validation-summary"]["artifact"],
            "psmatrix-2.0.0-final-validation-summary",
        )
        self.assertEqual(
            operations["public-oauth"]["authority"], operations["public-mtls"]["authority"]
        )
        self.assertTrue(value["all_evidence_must_share_control_head"])
        self.assertTrue(value["all_evidence_run_ids_must_be_distinct"])
        self.assertTrue(value["all_expected_artifacts_must_be_api_verified"])

    def test_wrong_final_release_commit_is_rejected(self) -> None:
        summary = self._summary(ready=False)
        summary["final_release_commit"] = "f" * 40
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(summary)

    def test_duplicate_readiness_environment_is_rejected(self) -> None:
        summary = self._summary(ready=False)
        summary["environments"][1] = copy.deepcopy(summary["environments"][0])
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(summary)

    def test_readiness_contract_check_count_drift_is_rejected(self) -> None:
        contract = copy.deepcopy(self.readiness_contract)
        contract["environments"][0]["required_secrets"] = []
        summary = self._summary(ready=False)
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(summary, readiness_contract=contract)

    def test_evaluator_gate_set_drift_is_rejected(self) -> None:
        contract = copy.deepcopy(self.evaluator_contract)
        contract["required_gates"] = contract["required_gates"][:-1]
        contract["evidence_sources"].pop("vulnerability-scan")
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(self._summary(ready=False), evaluator_contract=contract)

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

    def test_unknown_missing_requirement_is_rejected(self) -> None:
        summary = self._summary(ready=False)
        summary["environments"][0]["missing"].append("secret:NOT_IN_CONTRACT")
        with self.assertRaises(module.FinalValidationEvidenceChainError):
            self._build(summary)

    def test_control_head_must_be_exact_lowercase_sha(self) -> None:
        summary = self._summary(ready=False)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            readiness_path = root / "readiness-contract.json"
            evaluator_path = root / "evaluator-contract.json"
            summary_path = root / "summary.json"
            readiness_path.write_text(json.dumps(self.readiness_contract), encoding="utf-8")
            evaluator_path.write_text(json.dumps(self.evaluator_contract), encoding="utf-8")
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            with self.assertRaises(module.FinalValidationEvidenceChainError):
                module.build_plan(
                    readiness_contract_path=readiness_path,
                    evaluator_contract_path=evaluator_path,
                    readiness_summary_path=summary_path,
                    control_head="ABC",
                )


if __name__ == "__main__":
    unittest.main()
