from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"verify_final_lock_runs.py"
CONTRACT=ROOT/"ga-packs"/"03-authoritative-windows"/"final-release-lock-signing-control-contract.json"

def load():
    spec=importlib.util.spec_from_file_location("final_lock_api_verifier",SCRIPT)
    if spec is None or spec.loader is None: raise RuntimeError("load")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class FinalLockAPIVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.module=load(); cls.contract=json.loads(CONTRACT.read_text(encoding="utf-8")); cls.control="d"*40
    def _records(self):
        ledger={"schema":1,"kind":"psmatrix.final-release-lock-input-ledger","version":"2.0.0","final_candidate_commit":self.contract["final_release_commit"],"rc4_enrollment_run_id":101,"staging_run_id":102,"review_run_id":103,"reviewed_draft_sha256":"a"*64,"reviewed_public_key_sha256":"b"*64,"promotion_run_id":104,"lock_control_repository_commit":"c"*40,"active_lock_authority_verified":True}
        specs={"rc4_enrollment":(101,self.contract["rc4_authority_continuity"]["workflow"],self.contract["rc4_authority_continuity"]["artifact"],self.contract["rc4_authority_continuity"]["enrollment_control_head"]),"staging":(102,self.contract["final_staging"]["workflow"],self.contract["final_staging"]["artifact"],self.contract["final_release_commit"]),"review":(103,"production-ga-windows-authority-final-release-lock-review","psmatrix-2.0.0-final-release-lock-review",self.control),"promotion":(104,"production-ga-windows-authority-final-release-lock-promotion","psmatrix-2.0.0-final-release-lock-promotion-candidate",self.control)}
        runs={}; artifacts={}
        for index,(label,(run_id,workflow,artifact,head)) in enumerate(specs.items(),1):
            runs[label]={"id":run_id,"name":workflow,"event":"workflow_dispatch","status":"completed","conclusion":"success","head_sha":head}; artifacts[label]=[{"id":700+index,"name":artifact,"expired":False}]
        return ledger,runs,artifacts,{"lock":True,"public_key":True}
    def test_exact_four_runs_and_two_repository_targets_verify(self)->None:
        ledger,runs,artifacts,presence=self._records(); value=self.module.verify_records(ledger,self.contract,runs,artifacts,presence)
        self.assertEqual(value["status"],"PASS"); self.assertEqual(value["verified_run_count"],4); self.assertEqual(value["shared_review_promotion_control_head"],self.control); self.assertTrue(value["repository_lock_target_present"]); self.assertTrue(value["repository_public_key_target_present"]); self.assertFalse(value["repository_target_content_verified"]); self.assertFalse(value["release_signing_executed"]); self.assertFalse(value["ga_eligible"])
    def test_review_and_promotion_must_share_control_head(self)->None:
        ledger,runs,artifacts,presence=self._records(); runs["promotion"]["head_sha"]="e"*40
        with self.assertRaises(self.module.FinalLockVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,presence)
    def test_wrong_event_conclusion_or_frozen_upstream_head_fails(self)->None:
        for label,field,bad in (("review","event","push"),("promotion","conclusion","failure"),("staging","head_sha","f"*40),("rc4_enrollment","head_sha","0"*40)):
            ledger,runs,artifacts,presence=self._records(); runs[label][field]=bad
            with self.subTest(label=label,field=field):
                with self.assertRaises(self.module.FinalLockVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,presence)
    def test_missing_expired_or_duplicate_expected_artifact_fails(self)->None:
        ledger,runs,artifacts,presence=self._records(); artifacts["review"]=[]
        with self.assertRaises(self.module.FinalLockVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,presence)
        ledger,runs,artifacts,presence=self._records(); name=artifacts["promotion"][0]["name"]; artifacts["promotion"]=[{"id":1,"name":name,"expired":False},{"id":2,"name":name,"expired":False}]
        with self.assertRaises(self.module.FinalLockVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,presence)
    def test_both_repository_targets_must_exist_at_exact_commit(self)->None:
        ledger,runs,artifacts,presence=self._records(); presence["public_key"]=False
        with self.assertRaises(self.module.FinalLockVerificationError): self.module.verify_records(ledger,self.contract,runs,artifacts,presence)

if __name__=="__main__": unittest.main()
