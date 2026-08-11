from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"verify_final_evidence_runs.py"
CONTRACT=ROOT/"ga-packs"/"03-authoritative-windows"/"final-ga-evaluator-control-contract.json"

def load():
    spec=importlib.util.spec_from_file_location("evidence_api_verifier",SCRIPT)
    if spec is None or spec.loader is None: raise RuntimeError("load")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class FinalEvidenceAPIVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.module=load(); cls.contract=json.loads(CONTRACT.read_text(encoding="utf-8")); cls.head="a"*40
    def _records(self):
        ledger={"schema":1,"kind":"psmatrix.final-ga-evidence-run-ledger","version":"2.0.0","execution_head":self.head,"gates":{}}
        runs={}; artifacts={}; sources={}
        for index,gate in enumerate(self.contract["required_gates"],1):
            source=self.contract["evidence_sources"][gate]; run_id=9000+index; ledger["gates"][gate]={"workflow":source["workflow"],"artifact":source["artifact"],"authority":source["authority"],"run_id":run_id}; runs[gate]={"id":run_id,"event":"workflow_dispatch","status":"completed","conclusion":"success","head_sha":self.head,"name":source["workflow"]}; artifacts[gate]=[{"id":8000+index,"name":source["artifact"],"expired":False}]; sources[gate]=True
        return ledger,runs,artifacts,sources
    def test_exact_eleven_successful_distinct_runs_and_artifacts_verify(self)->None:
        ledger,runs,artifacts,sources=self._records(); value=self.module.verify_records(ledger,self.contract,runs,artifacts,sources)
        self.assertEqual(value["status"],"PASS"); self.assertEqual(value["verified_gate_count"],11); self.assertTrue(value["ready_for_final_ga_evaluator_dispatch"]); self.assertFalse(value["final_ga_evaluator_invoked"]); self.assertFalse(value["ga_eligible"])
    def test_non_workflow_dispatch_failed_or_wrong_head_run_fails(self)->None:
        for field,bad in (("event","push"),("conclusion","failure"),("head_sha","b"*40)):
            ledger,runs,artifacts,sources=self._records(); runs["public-oauth"][field]=bad
            with self.subTest(field=field):
                with self.assertRaises(self.module.EvidenceVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,sources)
    def test_missing_expired_or_duplicate_expected_artifact_fails(self)->None:
        for replacement in ([],[{"id":1,"name":self.contract["evidence_sources"]["external-otlp"]["artifact"],"expired":True}],[{"id":1,"name":self.contract["evidence_sources"]["external-otlp"]["artifact"],"expired":False},{"id":2,"name":self.contract["evidence_sources"]["external-otlp"]["artifact"],"expired":False}]):
            ledger,runs,artifacts,sources=self._records(); artifacts["external-otlp"]=replacement
            with self.assertRaises(self.module.EvidenceVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,sources)
    def test_wrong_workflow_or_missing_source_at_execution_head_fails(self)->None:
        ledger,runs,artifacts,sources=self._records(); runs["security-review"]["name"]="wrong-workflow"
        with self.assertRaises(self.module.EvidenceVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,sources)
        ledger,runs,artifacts,sources=self._records(); sources["vulnerability-scan"]=False
        with self.assertRaises(self.module.EvidenceVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,sources)
    def test_incomplete_ledger_never_reaches_api_verification(self)->None:
        ledger,runs,artifacts,sources=self._records(); ledger["gates"]["signed-release"]["run_id"]=None
        with self.assertRaises(self.module.EvidenceVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,sources)

if __name__=="__main__": unittest.main()
