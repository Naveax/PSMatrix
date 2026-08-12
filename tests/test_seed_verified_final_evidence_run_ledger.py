from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "seed_verified_final_evidence_run_ledger.py"
CONTRACT_PATH = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"

spec = importlib.util.spec_from_file_location("seed_verified_final_evidence_run_ledger", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SeedVerifiedFinalEvidenceRunLedgerTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def _anchor(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-execution-anchor-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "anchor_head": HEAD,
            "final_release_commit": FINAL_COMMIT,
            "publication_anchor_verified": True,
            "publication_commit_verified": True,
            "publication_ancestry_verified": True,
            "readiness_pass_observed": True,
            "post_readiness_run_count": 2,
            "current_stage": "POST_READINESS_EXECUTION_OBSERVED",
            "anchor_moved": False,
            "ga_eligible": False,
        }

    def _signing(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-release-signing-run-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 4101,
            "execution_head": HEAD,
            "workflow": "production-ga-windows-authority-final-release-sign-from-lock",
            "artifact": "psmatrix-2.0.0-protected-release",
            "artifact_id": 5101,
            "signed_release_run_verified": True,
            "ga_eligible": False,
        }

    def _protected(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.protected-final-release-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 4101,
            "execution_head": HEAD,
            "release_commit": FINAL_COMMIT,
            "artifact_content_verified": True,
            "signed_release_verified": True,
            "ga_eligible": False,
        }

    def _validation_run(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-validation-summary-run-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 4201,
            "execution_head": HEAD,
            "workflow": "production-ga-final-validation-summary",
            "artifact": "psmatrix-2.0.0-final-validation-summary",
            "artifact_id": 5201,
            "final_release_commit": FINAL_COMMIT,
            "release_signing_run_id": 4101,
            "release_signing_artifact_id": 5101,
            "release_signing_run_verified": True,
            "protected_release_content_verified": True,
            "validation_run_verified": True,
            "ga_eligible": False,
        }

    def _validation_bundle(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-validation-summary-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "final_release_commit": FINAL_COMMIT,
            "attestation_cryptographically_verified": True,
            "ci_authority_verified": True,
            "reproducibility_verified": True,
            "offline_install_verified": True,
            "ga_eligible": False,
        }

    def _seed(self, **overrides):
        values = {
            "contract": self._contract(),
            "execution_anchor_verification": self._anchor(),
            "signing_run_verification": self._signing(),
            "protected_release_verification": self._protected(),
            "validation_run_verification": self._validation_run(),
            "validation_bundle_verification": self._validation_bundle(),
        }
        values.update(overrides)
        return module.seed(**values)

    def test_seed_is_exact_incomplete_two_of_eleven_ledger(self) -> None:
        value = self._seed()
        self.assertEqual(value["execution_head"], HEAD)
        self.assertEqual(value["gates"]["validation-summary"]["run_id"], 4201)
        self.assertEqual(value["gates"]["signed-release"]["run_id"], 4101)
        missing = [gate for gate, row in value["gates"].items() if row["run_id"] is None]
        self.assertEqual(len(missing), 9)
        self.assertEqual(value["seed"]["verified_gate_count"], 2)
        self.assertEqual(value["seed"]["missing_gate_count"], 9)
        self.assertTrue(value["seed"]["ready_for_remaining_evidence_discovery"])
        self.assertFalse(value["seed"]["dispatch_input_release_signing_run_id_api_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_seed_rejects_wrong_execution_anchor(self) -> None:
        anchor = self._anchor()
        anchor["anchor_head"] = "f" * 40
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(execution_anchor_verification=anchor)

    def test_seed_rejects_stale_pre_post_readiness_anchor_receipt(self) -> None:
        anchor = self._anchor()
        anchor["readiness_pass_observed"] = False
        anchor["post_readiness_run_count"] = 0
        anchor["current_stage"] = "BLOCKED_ON_PRODUCTION_READINESS"
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(execution_anchor_verification=anchor)

    def test_seed_rejects_reused_run_ids(self) -> None:
        validation = self._validation_run()
        validation["run_id"] = 4101
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(validation_run_verification=validation)

    def test_seed_rejects_validation_binding_to_different_signing_run(self) -> None:
        validation = self._validation_run()
        validation["release_signing_run_id"] = 9999
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(validation_run_verification=validation)

    def test_seed_rejects_unverified_validation_content(self) -> None:
        bundle = self._validation_bundle()
        bundle["attestation_cryptographically_verified"] = False
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(validation_bundle_verification=bundle)

    def test_seed_rejects_gate_contract_drift(self) -> None:
        contract = self._contract()
        contract["evidence_sources"]["validation-summary"]["artifact"] = "wrong-artifact"
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(contract=contract)

    def test_seed_rejects_receipt_that_claims_ga_eligible(self) -> None:
        validation = self._validation_run()
        validation["ga_eligible"] = True
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(validation_run_verification=validation)

    def test_seed_rejects_invalid_signing_artifact_id(self) -> None:
        signing = self._signing()
        signing["artifact_id"] = 0
        with self.assertRaises(module.FinalEvidenceLedgerSeedError):
            self._seed(signing_run_verification=signing)


if __name__ == "__main__":
    unittest.main()
