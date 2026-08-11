from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_evidence_content_closure.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
spec = importlib.util.spec_from_file_location("content_closure", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


class FinalEvidenceContentClosureTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.api_rows = []
        for index, gate in enumerate(self.contract["required_gates"], 1):
            source = self.contract["evidence_sources"][gate]
            self.api_rows.append({"gate": gate, "run_id": 1000 + index, "workflow": source["workflow"], "artifact": source["artifact"], "artifact_id": 2000 + index, "authority": source["authority"], "verified": True})
        self.api = {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "verified_gate_count": 11, "gates": self.api_rows}

    def _single(self):
        bindings = []
        by_gate = {row["gate"]: row for row in self.api_rows}
        for gate in sorted(module.SINGLE_GATES):
            api = by_gate[gate]
            bindings.append({"schema": 1, "kind": "psmatrix.final-ga-evidence-content-binding", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "gate": gate, "run_id": api["run_id"], "artifact": api["artifact"], "artifact_id": api["artifact_id"], "materialized_tree_sha256": "b" * 64, "semantic_receipt_kind": f"semantic-{gate}", "semantic_receipt_sha256": "c" * 64, "api_artifact_origin_verified": True, "materialized_tree_verified": True, "semantic_verifier_repository_owned": True, "semantic_verification_mutated_tree": False, "content_semantics_verified": True, "final_ga_evaluator_invoked": False, "ga_eligible": False})
        return bindings

    def _public(self):
        by_gate = {row["gate"]: row for row in self.api_rows}
        return {"schema": 1, "kind": "psmatrix.public-auth-cross-gate-content-binding", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "covered_gates": ["public-oauth", "public-mtls"], "run_ids": {gate: by_gate[gate]["run_id"] for gate in module.PUBLIC_GATES}, "artifact_ids": {gate: by_gate[gate]["artifact_id"] for gate in module.PUBLIC_GATES}, "tree_sha256": {gate: "d" * 64 for gate in module.PUBLIC_GATES}, "semantic_receipt_sha256": "e" * 64, "api_artifact_origin_verified": True, "both_materialized_trees_verified": True, "semantic_verifier_repository_owned": True, "semantic_verification_mutated_tree": False, "content_semantics_verified": True, "cross_gate_semantics_verified": True, "final_ga_evaluator_invoked": False, "ga_eligible": False}

    def test_exact_eleven_gate_content_closure_passes(self):
        value = module.build(self.api, self.contract, self._single(), self._public())
        self.assertEqual(value["api_verified_gate_count"], 11)
        self.assertEqual(value["content_verified_gate_count"], 11)
        self.assertEqual([row["gate"] for row in value["gates"]], self.contract["required_gates"])
        self.assertTrue(value["ready_for_final_ga_evaluator_dispatch"])
        self.assertFalse(value["ga_eligible"])

    def test_missing_single_gate_fails_closed(self):
        with self.assertRaises(module.EvidenceContentClosureError):
            module.build(self.api, self.contract, self._single()[:-1], self._public())

    def test_run_id_drift_fails_closed(self):
        bindings = self._single()
        bindings[0]["run_id"] += 1
        with self.assertRaises(module.EvidenceContentClosureError):
            module.build(self.api, self.contract, bindings, self._public())

    def test_public_auth_artifact_drift_fails_closed(self):
        public = self._public()
        public["artifact_ids"]["public-oauth"] += 1
        with self.assertRaises(module.EvidenceContentClosureError):
            module.build(self.api, self.contract, self._single(), public)


if __name__ == "__main__":
    unittest.main()
