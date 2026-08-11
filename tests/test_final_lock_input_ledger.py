from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "validate_final_lock_input_ledger.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-lock-signing-control-contract.json"


def load():
    spec=importlib.util.spec_from_file_location("final_lock_ledger",SCRIPT)
    if spec is None or spec.loader is None: raise RuntimeError("load")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class FinalLockInputLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module=load(); cls.contract=json.loads(CONTRACT.read_text(encoding="utf-8")); cls.commit=cls.contract["final_release_commit"]

    def _empty(self) -> dict:
        return {"schema":1,"kind":"psmatrix.final-release-lock-input-ledger","version":"2.0.0","final_candidate_commit":None,"rc4_enrollment_run_id":None,"staging_run_id":None,"review_run_id":None,"reviewed_draft_sha256":None,"reviewed_public_key_sha256":None,"promotion_run_id":None,"lock_control_repository_commit":None,"active_lock_authority_verified":False}

    def _complete(self) -> dict:
        value=self._empty(); value.update({"final_candidate_commit":self.commit,"rc4_enrollment_run_id":101,"staging_run_id":102,"review_run_id":103,"reviewed_draft_sha256":"a"*64,"reviewed_public_key_sha256":"b"*64,"promotion_run_id":104,"lock_control_repository_commit":"c"*40,"active_lock_authority_verified":True}); return value

    def test_empty_ledger_is_incomplete_without_execution_claims(self) -> None:
        result=self.module.validate(self._empty(),self.contract)
        self.assertEqual(result["status"],"INCOMPLETE"); self.assertFalse(result["inputs_complete"]); self.assertFalse(result["workflow_success_verified"]); self.assertFalse(result["release_signing_executed"]); self.assertFalse(result["ga_eligible"])

    def test_syntactically_complete_ledger_is_not_execution_proof(self) -> None:
        result=self.module.validate(self._complete(),self.contract)
        self.assertEqual(result["status"],"INPUTS_COMPLETE_NOT_EXECUTION_PROOF"); self.assertTrue(result["inputs_complete"]); self.assertFalse(result["workflow_success_verified"]); self.assertFalse(result["artifact_identity_verified"]); self.assertFalse(result["repository_lock_files_verified"])

    def test_candidate_must_equal_frozen_final_release_commit(self) -> None:
        value=self._complete(); value["final_candidate_commit"]="d"*40
        with self.assertRaises(self.module.FinalLockLedgerError): self.module.validate(value,self.contract)

    def test_run_ids_must_be_positive_and_distinct(self) -> None:
        value=self._complete(); value["review_run_id"]=value["staging_run_id"]
        with self.assertRaises(self.module.FinalLockLedgerError): self.module.validate(value,self.contract)
        value=self._complete(); value["promotion_run_id"]=0
        with self.assertRaises(self.module.FinalLockLedgerError): self.module.validate(value,self.contract)

    def test_reviewed_digests_and_repository_commit_are_exact_lowercase_hex(self) -> None:
        value=self._complete(); value["reviewed_draft_sha256"]="A"*64
        with self.assertRaises(self.module.FinalLockLedgerError): self.module.validate(value,self.contract)
        value=self._complete(); value["lock_control_repository_commit"]="z"*40
        with self.assertRaises(self.module.FinalLockLedgerError): self.module.validate(value,self.contract)

if __name__=="__main__": unittest.main()
