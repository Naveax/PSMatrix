from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "complete_verified_final_evidence_run_ledger.py"
CONTRACT_PATH = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"

spec = importlib.util.spec_from_file_location("complete_verified_final_evidence_run_ledger", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompleteVerifiedFinalEvidenceRunLedgerTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def _seed(self) -> dict:
        contract = self._contract()
        gates = {}
        for gate in contract["required_gates"]:
            source = contract["evidence_sources"][gate]
            run_id = None
            if gate == "validation-summary":
                run_id = 4201
            elif gate == "signed-release":
                run_id = 4101
            gates[gate] = {
                "workflow": source["workflow"],
                "artifact": source["artifact"],
                "authority": source["authority"],
                "run_id": run_id,
            }
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-run-ledger",
            "version": "2.0.0",
            "execution_head": HEAD,
            "gates": gates,
            "seed": {
                "verified_gate_count": 2,
                "verified_gates": ["validation-summary", "signed-release"],
                "missing_gate_count": 9,
                "ready_for_remaining_evidence_discovery": True,
                "signed_release_artifact_id": 5101,
                "validation_summary_artifact_id": 5201,
            },
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }

    def _remaining_evidence(self):
        contract = self._contract()
        missing = [gate for gate in contract["required_gates"] if gate not in {"validation-summary", "signed-release"}]
        runs = []
        artifacts = {}
        for index, gate in enumerate(missing, start=1):
            source = contract["evidence_sources"][gate]
            run_id = 6000 + index
            artifact_id = 7000 + index
            runs.append(
                {
                    "id": run_id,
                    "name": source["workflow"],
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": HEAD,
                }
            )
            artifacts[run_id] = [
                {
                    "id": artifact_id,
                    "name": source["artifact"],
                    "expired": False,
                }
            ]
        return runs, artifacts

    def test_completion_preserves_seed_and_fills_exact_remaining_nine(self) -> None:
        seed = self._seed()
        runs, artifacts = self._remaining_evidence()
        value = module.complete(
            seed_ledger=seed,
            contract=self._contract(),
            runs=runs,
            artifacts_by_run=artifacts,
        )
        self.assertEqual(value["gates"]["validation-summary"]["run_id"], 4201)
        self.assertEqual(value["gates"]["signed-release"]["run_id"], 4101)
        self.assertEqual(sum(row["run_id"] is not None for row in value["gates"].values()), 11)
        self.assertEqual(value["completion"]["seeded_gate_count"], 2)
        self.assertEqual(value["completion"]["discovered_gate_count"], 9)
        self.assertTrue(value["completion"]["all_run_ids_distinct"])
        self.assertTrue(value["completion"]["ready_for_final_ga_evidence_api_verification"])
        self.assertFalse(value["completion"]["final_ga_evidence_api_verified"])
        self.assertFalse(value["final_ga_evaluator_invoked"])
        self.assertFalse(value["ga_eligible"])

    def test_completion_rejects_non_two_of_eleven_seed(self) -> None:
        seed = self._seed()
        seed["gates"]["authoritative-windows"]["run_id"] = 9999
        runs, artifacts = self._remaining_evidence()
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.complete(
                seed_ledger=seed,
                contract=self._contract(),
                runs=runs,
                artifacts_by_run=artifacts,
            )

    def test_completion_rejects_ambiguous_remaining_gate(self) -> None:
        contract = self._contract()
        runs, artifacts = self._remaining_evidence()
        source = contract["evidence_sources"]["authoritative-windows"]
        duplicate = {
            "id": 9001,
            "name": source["workflow"],
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": HEAD,
        }
        runs.append(duplicate)
        artifacts[9001] = [{"id": 9101, "name": source["artifact"], "expired": False}]
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.complete(
                seed_ledger=self._seed(),
                contract=contract,
                runs=runs,
                artifacts_by_run=artifacts,
            )

    def test_completion_rejects_wrong_head_candidate(self) -> None:
        runs, artifacts = self._remaining_evidence()
        runs[0]["head_sha"] = "f" * 40
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.complete(
                seed_ledger=self._seed(),
                contract=self._contract(),
                runs=runs,
                artifacts_by_run=artifacts,
            )

    def test_completion_rejects_expired_or_missing_artifact(self) -> None:
        runs, artifacts = self._remaining_evidence()
        artifacts[runs[0]["id"]][0]["expired"] = True
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.complete(
                seed_ledger=self._seed(),
                contract=self._contract(),
                runs=runs,
                artifacts_by_run=artifacts,
            )

    def test_completion_rejects_run_id_reuse_with_seed(self) -> None:
        runs, artifacts = self._remaining_evidence()
        first_id = runs[0]["id"]
        runs[0]["id"] = 4101
        artifacts[4101] = artifacts.pop(first_id)
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.complete(
                seed_ledger=self._seed(),
                contract=self._contract(),
                runs=runs,
                artifacts_by_run=artifacts,
            )

    def test_live_collection_repository_scope_is_frozen(self) -> None:
        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module.collect_live(
                seed_ledger=self._seed(),
                contract=self._contract(),
                repository="SomeoneElse/PSMatrix",
                api_get=lambda endpoint: {},
            )

    def test_paged_listing_collects_all_rows(self) -> None:
        rows = [{"id": index + 1} for index in range(101)]
        calls = []

        def endpoint(page: int) -> str:
            return f"items?page={page}"

        def api_get(value: str):
            page = int(parse_qs(urlparse("https://x.invalid/?" + value.split("?", 1)[1]).query)["page"][0])
            calls.append(page)
            if page == 1:
                return {"total_count": 101, "workflow_runs": rows[:100]}
            if page == 2:
                return {"total_count": 101, "workflow_runs": rows[100:]}
            raise AssertionError("unexpected page")

        value = module._paged_listing(api_get, endpoint, rows_key="workflow_runs", label="test rows")
        self.assertEqual(len(value), 101)
        self.assertEqual(calls, [1, 2])

    def test_paged_listing_rejects_count_drift(self) -> None:
        rows = [{"id": index + 1} for index in range(101)]

        def endpoint(page: int) -> str:
            return f"items?page={page}"

        def api_get(value: str):
            page = int(value.rsplit("=", 1)[1])
            if page == 1:
                return {"total_count": 101, "workflow_runs": rows[:100]}
            return {"total_count": 100, "workflow_runs": rows[100:]}

        with self.assertRaises(module.FinalEvidenceLedgerCompletionError):
            module._paged_listing(api_get, endpoint, rows_key="workflow_runs", label="test rows")


if __name__ == "__main__":
    unittest.main()
