from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "bind_final_validation_evidence_chain_preflight.py"
HEAD = "06c80421ecb8c6668e5e4334f9138a55ae56e1fd"
FINAL_RELEASE = "02cef95d40cf524ce00f9d917188343dc49e6f2c"

spec = importlib.util.spec_from_file_location("final_validation_evidence_chain_preflight", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationEvidenceChainPreflightTests(unittest.TestCase):
    def _plan(self, *, ready: bool) -> dict:
        passed = 12 if ready else 0
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-final-validation-evidence-chain-plan",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "control_head": HEAD,
            "final_release_commit": FINAL_RELEASE,
            "required_check_count": 41,
            "environment_count": 12,
            "environment_passed": passed,
            "environment_failed": 12 - passed,
            "readiness_status": "PASS" if ready else "FAIL",
            "ready_for_final_release_signing": ready,
            "evaluator_gate_count": 11,
            "evidence_operations": [{"gate": str(index)} for index in range(11)],
            "production_state_mutated": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def _control(self, *, signing: str = "NOT_EXECUTED", validation: str = "NOT_EXECUTED") -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-final-validation-control-plane-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "control_head": HEAD,
            "all_control_runs_completed_successfully": True,
            "all_control_runs_are_main_push": True,
            "all_control_runs_share_control_head": True,
            "control_run_ids_distinct": True,
            "protected_final_release_signing": {
                "state": signing,
                "successful_workflow_dispatch": signing == "COMPLETED_SUCCESS",
            },
            "protected_final_validation_summary": {
                "state": validation,
                "successful_workflow_dispatch": validation == "COMPLETED_SUCCESS",
            },
            "production_state_mutated": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def test_blocked_readiness_remains_blocked_on_production_material(self) -> None:
        value = module.bind(self._plan(ready=False), self._control())
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_MATERIAL")
        self.assertEqual(value["environment_passed"], 0)
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_ready_without_signing_advances_only_to_release_signing(self) -> None:
        value = module.bind(self._plan(ready=True), self._control())
        self.assertEqual(value["current_stage"], "READY_FOR_FINAL_RELEASE_SIGNING")
        self.assertFalse(value["ga_eligible"])

    def test_successful_signing_advances_only_to_protected_final_validation(self) -> None:
        value = module.bind(
            self._plan(ready=True), self._control(signing="COMPLETED_SUCCESS")
        )
        self.assertEqual(value["current_stage"], "READY_FOR_PROTECTED_FINAL_VALIDATION")
        self.assertFalse(value["ga_eligible"])

    def test_successful_validation_advances_only_to_evidence_collection(self) -> None:
        value = module.bind(
            self._plan(ready=True),
            self._control(
                signing="COMPLETED_SUCCESS", validation="COMPLETED_SUCCESS"
            ),
        )
        self.assertEqual(value["current_stage"], "READY_FOR_EVIDENCE_RUN_COLLECTION")
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["final_ga_evaluator_invoked"])

    def test_protected_signing_cannot_exist_while_readiness_is_blocked(self) -> None:
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=False), self._control(signing="COMPLETED_SUCCESS")
            )

    def test_validation_cannot_precede_signing(self) -> None:
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=True), self._control(validation="COMPLETED_SUCCESS")
            )

    def test_unsuccessful_signing_is_an_explicit_blocker(self) -> None:
        value = module.bind(
            self._plan(ready=True), self._control(signing="OBSERVED_NOT_SUCCESSFUL")
        )
        self.assertEqual(
            value["current_stage"], "BLOCKED_ON_PROTECTED_FINAL_RELEASE_SIGNING"
        )

    def test_unsuccessful_validation_after_signing_is_an_explicit_blocker(self) -> None:
        value = module.bind(
            self._plan(ready=True),
            self._control(
                signing="COMPLETED_SUCCESS", validation="OBSERVED_NOT_SUCCESSFUL"
            ),
        )
        self.assertEqual(
            value["current_stage"], "BLOCKED_ON_PROTECTED_FINAL_VALIDATION"
        )

    def test_control_head_mismatch_is_rejected(self) -> None:
        control = self._control()
        control["control_head"] = "f" * 40
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(self._plan(ready=True), control)

    def test_any_premature_ga_or_release_claim_is_rejected(self) -> None:
        for target in ("plan", "control"):
            for field in ("ga_eligible", "release_closed", "production_state_mutated"):
                with self.subTest(target=target, field=field):
                    plan = self._plan(ready=True)
                    control = self._control()
                    if target == "plan":
                        plan[field] = True
                    else:
                        control[field] = True
                    with self.assertRaises(module.FinalValidationEvidencePreflightError):
                        module.bind(plan, control)

    def test_lost_control_plane_invariant_is_rejected(self) -> None:
        for field in (
            "all_control_runs_completed_successfully",
            "all_control_runs_are_main_push",
            "all_control_runs_share_control_head",
            "control_run_ids_distinct",
        ):
            with self.subTest(field=field):
                control = copy.deepcopy(self._control())
                control[field] = False
                with self.assertRaises(module.FinalValidationEvidencePreflightError):
                    module.bind(self._plan(ready=True), control)


if __name__ == "__main__":
    unittest.main()
