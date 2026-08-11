from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"validate_final_evidence_run_ledger.py"
CONTRACT=ROOT/"ga-packs"/"03-authoritative-windows"/"final-ga-evaluator-control-contract.json"

def load():
    spec=importlib.util.spec_from_file_location("evidence_ledger",SCRIPT)
    if spec is None or spec.loader is None: raise RuntimeError("load")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class FinalEvidenceRunLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.module=load(); cls.contract=json.loads(CONTRACT.read_text(encoding="utf-8")); cls.gates=cls.contract["required_gates"]
    def _ledger(self,complete:bool=False)->dict:
        rows={}
        for index,gate in enumerate(self.gates,1):
            source=self.contract["evidence_sources"][gate]; rows[gate]={"workflow":source["workflow"],"artifact":source["artifact"],"authority":source["authority"],"run_id":1000+index if complete else None}
        return {"schema":1,"kind":"psmatrix.final-ga-evidence-run-ledger","version":"2.0.0","execution_head":"a"*40 if complete else None,"gates":rows}
    def test_empty_exact_gate_ledger_is_incomplete_and_never_evaluator_claim(self)->None:
        value=self.module.validate(self._ledger(),self.contract); self.assertEqual(value["status"],"INCOMPLETE"); self.assertEqual(value["present_run_id_count"],0); self.assertEqual(len(value["missing_gates"]),11); self.assertFalse(value["final_ga_evaluator_invoked"]); self.assertFalse(value["ga_eligible"])
    def test_complete_ledger_is_only_input_complete_not_evaluated(self)->None:
        value=self.module.validate(self._ledger(True),self.contract); self.assertEqual(value["status"],"INPUTS_COMPLETE_NOT_EVALUATED"); self.assertTrue(value["inputs_complete"]); self.assertEqual(value["present_run_id_count"],11); self.assertFalse(value["workflow_dispatch_verified"]); self.assertFalse(value["workflow_success_verified"]); self.assertFalse(value["artifact_identity_verified"]); self.assertFalse(value["shared_execution_head_verified"])
    def test_duplicate_run_ids_fail_closed(self)->None:
        ledger=self._ledger(True); ledger["gates"][self.gates[1]]["run_id"]=ledger["gates"][self.gates[0]]["run_id"]
        with self.assertRaises(self.module.EvidenceLedgerError): self.module.validate(ledger,self.contract)
    def test_gate_source_identity_must_match_contract(self)->None:
        ledger=self._ledger(True); ledger["gates"]["public-oauth"]["authority"]="release"
        with self.assertRaises(self.module.EvidenceLedgerError): self.module.validate(ledger,self.contract)
    def test_gate_closure_must_be_exactly_eleven(self)->None:
        ledger=self._ledger(); ledger["gates"].pop(self.gates[-1])
        with self.assertRaises(self.module.EvidenceLedgerError): self.module.validate(ledger,self.contract)

if __name__=="__main__": unittest.main()
