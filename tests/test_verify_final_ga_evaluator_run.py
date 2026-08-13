from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_evaluator_run.py"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"

spec = importlib.util.spec_from_file_location("verify_final_ga_evaluator_run", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VerifyFinalGAEvaluatorRunTests(unittest.TestCase):
    def _closure(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-content-closure",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": HEAD,
            "required_gate_count": 11,
            "api_verified_gate_count": 11,
            "content_verified_gate_count": 11,
            "all_api_artifact_origins_verified": True,
            "all_materialized_trees_verified": True,
            "all_repository_owned_semantic_verifiers_passed": True,
            "all_gate_contents_verified": True,
            "public_auth_cross_gate_semantics_verified": True,
            "all_runs_distinct": True,
            "all_artifacts_distinct": True,
            "ready_for_final_ga_evaluator_dispatch": True,
            "final_ga_evaluator_invoked": False,
            "ga_root_private_key_read": False,
            "ga_eligible": False,
            "gates": [{"gate": f"gate-{index}"} for index in range(11)],
        }

    def _closure_verification(self, closure: dict, closure_file_sha256: str) -> dict:
        canonical = hashlib.sha256(
            json.dumps(closure, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-content-closure-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": HEAD,
            "single_binding_count": 9,
            "public_auth_binding_count": 1,
            "source_binding_receipt_count": 10,
            "verified_gate_count": 11,
            "closure_canonical_sha256": canonical,
            "repository_owned_rederivation": True,
            "closure_exactly_recomputed": True,
            "ready_for_final_ga_evaluator_dispatch": True,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
            "content_closure_file_sha256": closure_file_sha256,
        }

    def _run(self) -> dict:
        return {
            "id": 12345,
            "name": "production-ga-final-evaluator",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": HEAD,
        }

    def _artifacts(self) -> list[dict]:
        return [{"id": 98765, "name": "psmatrix-2.0.0-final-ga-attestation", "expired": False}]

    def _verify(self, *, closure: dict | None = None, verification: dict | None = None) -> dict:
        closure = self._closure() if closure is None else closure
        closure_bytes = (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8")
        closure_sha = hashlib.sha256(closure_bytes).hexdigest()
        verification = self._closure_verification(closure, closure_sha) if verification is None else verification
        verification_bytes = (json.dumps(verification, indent=2, sort_keys=True) + "\n").encode("utf-8")
        return module.verify(
            12345,
            HEAD,
            closure,
            verification,
            closure_sha,
            len(closure_bytes),
            hashlib.sha256(verification_bytes).hexdigest(),
            len(verification_bytes),
            self._run(),
            self._artifacts(),
        )

    def test_preserves_exact_content_closure_reverification_byte_provenance(self) -> None:
        value = self._verify()
        self.assertTrue(value["content_closure_reverification_required"])
        self.assertTrue(value["content_closure_repository_owned_rederivation"])
        self.assertTrue(value["content_closure_exactly_recomputed"])
        self.assertRegex(value["content_closure_file_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(value["content_closure_file_size"], 0)
        self.assertRegex(value["content_closure_reverification_file_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(value["content_closure_reverification_file_size"], 0)
        self.assertFalse(value["ga_eligible"])

    def test_rejects_reverification_bound_to_different_raw_closure_bytes(self) -> None:
        closure = self._closure()
        closure_bytes = (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8")
        verification = self._closure_verification(closure, hashlib.sha256(closure_bytes).hexdigest())
        verification["content_closure_file_sha256"] = "0" * 64
        with self.assertRaisesRegex(module.FinalGAEvaluatorRunError, "bytes differ"):
            self._verify(closure=closure, verification=verification)

    def test_rejects_unrederived_reverification_receipt(self) -> None:
        closure = self._closure()
        closure_bytes = (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8")
        verification = self._closure_verification(closure, hashlib.sha256(closure_bytes).hexdigest())
        verification["repository_owned_rederivation"] = False
        with self.assertRaisesRegex(module.FinalGAEvaluatorRunError, "repository_owned_rederivation"):
            self._verify(closure=closure, verification=verification)

    def test_rejects_canonical_digest_mismatch(self) -> None:
        closure = self._closure()
        closure_bytes = (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8")
        verification = self._closure_verification(closure, hashlib.sha256(closure_bytes).hexdigest())
        verification["closure_canonical_sha256"] = "f" * 64
        with self.assertRaisesRegex(module.FinalGAEvaluatorRunError, "canonical digest"):
            self._verify(closure=closure, verification=verification)


if __name__ == "__main__":
    unittest.main()
