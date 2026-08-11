from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_release_closure_from_attestation_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("release_closure_attestation_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseClosureAttestationHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.head = "a" * 40
        self.verification_path = self.root / "final-attestation-verification.json"
        self.verification = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_control_head": self.head,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.verification_path.write_text(json.dumps(self.verification) + "\n", encoding="utf-8")
        digest = hashlib.sha256(self.verification_path.read_bytes()).hexdigest()
        self.operation_path = self.root / "operation.json"
        self.operation = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-content-operation",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": self.head,
            "verification_receipt": str(self.verification_path),
            "verification_receipt_sha256": digest,
            "exact_api_artifact_id_used": True,
            "safe_extraction_verified": True,
            "semantic_verifier_repository_owned": True,
            "semantic_verification_mutated_tree": False,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.operation_path.write_text(json.dumps(self.operation) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_attestation_operation_resolves_bound_verification(self) -> None:
        value, path = self.module.resolve_attestation_verification(self.operation, self.operation_path)
        self.assertEqual(value["execution_control_head"], self.head)
        self.assertEqual(path, self.verification_path.resolve())

    def test_verification_digest_tamper_fails_closed(self) -> None:
        self.operation["verification_receipt_sha256"] = "0" * 64
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_execution_head_drift_fails_closed(self) -> None:
        self.verification["execution_control_head"] = "b" * 40
        self.verification_path.write_text(json.dumps(self.verification) + "\n", encoding="utf-8")
        self.operation["verification_receipt_sha256"] = hashlib.sha256(self.verification_path.read_bytes()).hexdigest()
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_tree_mutation_flag_fails_closed(self) -> None:
        self.operation["semantic_verification_mutated_tree"] = True
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_source_delegates_to_existing_five_precondition_builder(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_release_closure_readiness.py", text)
        self.assertIn("builder.build", text)
        self.assertIn("verification_receipt_sha256", text)
        self.assertIn("READY_FOR_RELEASE_CLOSURE", text)
        self.assertIn("release_closed=false", text)


if __name__ == "__main__":
    unittest.main()
