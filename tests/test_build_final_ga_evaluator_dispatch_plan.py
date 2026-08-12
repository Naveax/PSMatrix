from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_ga_evaluator_dispatch_plan.py"
CONTRACT_PATH = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"

spec = importlib.util.spec_from_file_location("build_final_ga_evaluator_dispatch_plan", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BuildFinalGAEvaluatorDispatchPlanTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def _ledger(self) -> dict:
        contract = self._contract()
        gates = {}
        for index, gate in enumerate(contract["required_gates"], start=1):
            source = contract["evidence_sources"][gate]
            gates[gate] = {
                "workflow": source["workflow"],
                "artifact": source["artifact"],
                "authority": source["authority"],
                "run_id": 8000 + index,
            }
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-run-ledger",
            "version": "2.0.0",
            "execution_head": HEAD,
            "gates": gates,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }

    def _api(self) -> dict:
        contract = self._contract()
        ledger = self._ledger()
        rows = []
        for index, gate in enumerate(contract["required_gates"], start=1):
            source = contract["evidence_sources"][gate]
            rows.append(
                {
                    "gate": gate,
                    "run_id": ledger["gates"][gate]["run_id"],
                    "workflow": source["workflow"],
                    "artifact": source["artifact"],
                    "artifact_id": 9000 + index,
                    "authority": source["authority"],
                    "verified": True,
                }
            )
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": HEAD,
            "required_gate_count": 11,
            "verified_gate_count": 11,
            "gates": rows,
            "all_runs_workflow_dispatch": True,
            "all_runs_completed_successfully": True,
            "all_runs_share_execution_head": True,
            "all_expected_artifacts_unique_and_nonexpired": True,
            "all_producer_workflow_sources_present": True,
            "ready_for_final_ga_evaluator_dispatch": True,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }

    def test_plan_maps_all_eleven_verified_gate_ids_to_frozen_workflow_inputs(self) -> None:
        ledger = self._ledger()
        value = module.build(
            ledger=ledger,
            api_verification=self._api(),
            contract=self._contract(),
        )
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["workflow"], "production-ga-final-evaluator")
        self.assertEqual(value["workflow_path"], ".github/workflows/ga-final-evaluator.yml")
        self.assertEqual(value["ref"], "final/2.0.0-production-control-plane-publication-anchor")
        self.assertEqual(value["execution_head"], HEAD)
        self.assertEqual(len(value["workflow_dispatch_inputs"]), 11)
        self.assertEqual(value["workflow_dispatch_inputs"]["validation_run_id"], "8001")
        self.assertEqual(value["workflow_dispatch_inputs"]["release_signing_run_id"], "8002")
        self.assertEqual(value["workflow_dispatch_inputs"]["vulnerability_scan_run_id"], "8011")
        self.assertTrue(value["run_ids_distinct"])
        self.assertTrue(value["final_evidence_api_verified"])
        self.assertFalse(value["dispatch_performed"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_plan_rejects_incomplete_ledger(self) -> None:
        ledger = self._ledger()
        ledger["gates"]["external-otlp"]["run_id"] = None
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=ledger, api_verification=self._api(), contract=self._contract())

    def test_plan_rejects_wrong_execution_head(self) -> None:
        ledger = self._ledger()
        ledger["execution_head"] = "f" * 40
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=ledger, api_verification=self._api(), contract=self._contract())

    def test_plan_rejects_api_run_id_mismatch(self) -> None:
        api = self._api()
        api["gates"][0]["run_id"] = 999999
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=self._ledger(), api_verification=api, contract=self._contract())

    def test_plan_rejects_api_verification_without_dispatch_readiness(self) -> None:
        api = self._api()
        api["ready_for_final_ga_evaluator_dispatch"] = False
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=self._ledger(), api_verification=api, contract=self._contract())

    def test_plan_rejects_api_gate_order_drift(self) -> None:
        api = self._api()
        api["gates"][0], api["gates"][1] = api["gates"][1], api["gates"][0]
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=self._ledger(), api_verification=api, contract=self._contract())

    def test_plan_rejects_api_artifact_identity_drift(self) -> None:
        api = self._api()
        api["gates"][3]["artifact"] = "wrong-artifact"
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=self._ledger(), api_verification=api, contract=self._contract())

    def test_plan_rejects_any_pre_evaluator_ga_claim(self) -> None:
        ledger = self._ledger()
        ledger["ga_eligible"] = True
        with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
            module.build(ledger=ledger, api_verification=self._api(), contract=self._contract())


if __name__ == "__main__":
    unittest.main()
