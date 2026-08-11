from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "discover_final_evidence_run_ledger.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
spec = importlib.util.spec_from_file_location("evidence_discovery", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


class FinalEvidenceRunLedgerDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.runs = []
        self.artifacts = {}
        for index, gate in enumerate(self.contract["required_gates"], 1):
            source = self.contract["evidence_sources"][gate]
            run_id = 1000 + index
            self.runs.append({"id": run_id, "name": source["workflow"], "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_sha": HEAD})
            self.artifacts[run_id] = [{"id": 2000 + index, "name": source["artifact"], "expired": False}]

    def test_exact_unambiguous_eleven_run_set_builds_ledger(self):
        value = module.discover(self.contract, HEAD, self.runs, self.artifacts)
        self.assertEqual(len(value["gates"]), 11)
        self.assertEqual(len({row["run_id"] for row in value["gates"].values()}), 11)
        self.assertFalse(value["discovery"]["ambiguity_allowed"])
        self.assertFalse(value["ga_eligible"])

    def test_second_eligible_run_for_gate_fails_ambiguous(self):
        first_gate = self.contract["required_gates"][0]
        source = self.contract["evidence_sources"][first_gate]
        self.runs.append({"id": 9999, "name": source["workflow"], "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_sha": HEAD})
        self.artifacts[9999] = [{"id": 8888, "name": source["artifact"], "expired": False}]
        with self.assertRaises(module.EvidenceDiscoveryError):
            module.discover(self.contract, HEAD, self.runs, self.artifacts)

    def test_expired_only_artifact_fails_closed(self):
        first_id = self.runs[0]["id"]
        self.artifacts[first_id][0]["expired"] = True
        with self.assertRaises(module.EvidenceDiscoveryError):
            module.discover(self.contract, HEAD, self.runs, self.artifacts)


if __name__ == "__main__":
    unittest.main()
