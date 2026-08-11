from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"build_production_ga_operator_dashboard.py"

def load():
    spec=importlib.util.spec_from_file_location("ga_operator_dashboard",SCRIPT)
    if spec is None or spec.loader is None: raise RuntimeError("load")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class ProductionGAOperatorDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None: cls.module=load()
    def _inventory(self,present:int)->dict:
        return {"schema":1,"kind":"psmatrix.production-ga-environment-inventory-audit","version":"2.0.0","environment_count":12,"required_check_count":41,"present_check_count":present,"missing_check_count":41-present}
    def _readiness(self,passed:bool)->dict:
        return {"schema":1,"kind":"psmatrix.production-readiness-summary","version":"2.0.0","environment_count":12,"status":"PASS" if passed else "FAIL","environment_passed":12 if passed else 0,"environment_failed":0 if passed else 12,"environment_readiness":passed}
    def _lock(self)->dict:
        return {"schema":1,"kind":"psmatrix.final-release-lock-api-verification","version":"2.0.0","status":"PASS","run_and_artifact_provenance_verified":True,"repository_target_presence_verified":True}
    def _evidence(self)->dict:
        return {"schema":1,"kind":"psmatrix.final-ga-evidence-api-verification","version":"2.0.0","status":"PASS","verified_gate_count":11,"ready_for_final_ga_evaluator_dispatch":True}
    def test_zero_of_forty_one_stays_in_provisioning(self)->None:
        value=self.module.build(self._inventory(0),self._readiness(False)); self.assertEqual(value["stage"],"PROVISION_ENVIRONMENTS"); self.assertFalse(value["ga_eligible"])
    def test_forty_one_names_but_failed_readiness_requires_rerun(self)->None:
        value=self.module.build(self._inventory(41),self._readiness(False)); self.assertEqual(value["stage"],"RERUN_PRODUCTION_READINESS"); self.assertFalse(value["production_readiness_pass"])
    def test_real_readiness_pass_without_lock_verification_stops_at_lock(self)->None:
        value=self.module.build(self._inventory(41),self._readiness(True)); self.assertEqual(value["stage"],"EXECUTE_AND_VERIFY_FINAL_LOCK"); self.assertTrue(value["production_readiness_pass"]); self.assertFalse(value["final_lock_api_verification_pass"])
    def test_verified_lock_without_evidence_stops_at_evidence(self)->None:
        value=self.module.build(self._inventory(41),self._readiness(True),self._lock()); self.assertEqual(value["stage"],"RUN_AND_VERIFY_PRODUCTION_EVIDENCE"); self.assertTrue(value["final_lock_api_verification_pass"]); self.assertFalse(value["final_evidence_api_verification_pass"])
    def test_verified_eleven_gate_evidence_allows_only_evaluator_dispatch_not_ga(self)->None:
        value=self.module.build(self._inventory(41),self._readiness(True),self._lock(),self._evidence()); self.assertEqual(value["stage"],"DISPATCH_FINAL_GA_EVALUATOR"); self.assertTrue(value["final_evidence_api_verification_pass"]); self.assertFalse(value["final_ga_evaluator_invoked"]); self.assertFalse(value["ga_root_signing_completed"]); self.assertFalse(value["final_ga_attestation_verified"]); self.assertFalse(value["ga_eligible"])
    def test_bad_inventory_cardinality_fails_closed(self)->None:
        inventory=self._inventory(41); inventory["required_check_count"]=40
        with self.assertRaises(self.module.OperatorDashboardError): self.module.build(inventory,self._readiness(False))

if __name__=="__main__": unittest.main()
