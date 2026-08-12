from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_final_ga_attestation_public_asset.py"
VERIFIER = ROOT / "scripts" / "ga" / "verify_final_ga_attestation_public_asset.py"
ASSET_NAME = "psmatrix-2.0.0-final-ga-attestation.zip"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAAttestationPublicReleaseAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load(BUILDER, "final_ga_attestation_public_asset_builder_test")
        self.verifier = load(VERIFIER, "final_ga_attestation_public_asset_verifier_test")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.head = "a" * 40
        payloads = {
            "final-ga-attestation-status.json": b'{"status":"PASS"}\n',
            "final-ga-evaluator-candidate-status.json": b'{"status":"ALL_11_GATES_PASS_ROOT_SIGNING_PENDING"}\n',
            "final-ga-run-provenance.json": b'{"runs":{}}\n',
            "ga-policy.json": b'{"policy":"test"}\n',
            "psmatrix-2.0.0-final-ga.dsse.json": b'{"payloadType":"application/vnd.in-toto+json"}\n',
            "psmatrix-2.0.0-final-ga-verification.json": b'{"valid":true}\n',
            "psmatrix-2.0.0-ga-root-public.pem": b"-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
            "SHA256SUMS.txt": b"test sums\n",
        }
        for name, data in payloads.items():
            (self.bundle / name).write_bytes(data)
        self.verification = self.root / "final-attestation-verification.json"
        verification_value = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_control_head": self.head,
            "required_gate_count": 11,
            "provenance_run_count": 11,
            "sha256_manifest_verified": True,
            "private_key_material_absent": True,
            "dsse_cryptographically_verified": True,
            "root_release_authorities_independent": True,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.verification.write_text(json.dumps(verification_value, sort_keys=True) + "\n", encoding="utf-8")
        self.semantic_verifier = patch.object(
            self.verifier._BUNDLE_VERIFIER,
            "verify",
            return_value=dict(verification_value),
        )
        self.semantic_verify = self.semantic_verifier.start()
        tree_sha, files, _ = self.verifier._bundle_state(self.bundle)
        self.operation = self.root / "attestation-operation.json"
        operation_value = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-content-operation",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": self.head,
            "evaluator_run_id": 123,
            "artifact": "psmatrix-2.0.0-final-ga-attestation",
            "artifact_id": 456,
            "materialized_file_count": len(files),
            "materialized_tree_sha256": tree_sha,
            "verification_receipt": str(self.verification),
            "verification_receipt_sha256": hashlib.sha256(self.verification.read_bytes()).hexdigest(),
            "exact_api_artifact_id_used": True,
            "safe_extraction_verified": True,
            "semantic_verifier_repository_owned": True,
            "semantic_verification_mutated_tree": False,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.operation.write_text(json.dumps(operation_value, sort_keys=True) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.semantic_verifier.stop()
        self.temp.cleanup()

    def build(self, suffix: str):
        asset_dir = self.root / suffix
        asset_dir.mkdir()
        asset = asset_dir / ASSET_NAME
        value = self.builder.build(self.operation, self.bundle, asset)
        return value, asset

    def test_deterministic_zip_is_reproducible_and_reverified_against_current_tree(self) -> None:
        first, first_path = self.build("one")
        second, second_path = self.build("two")
        self.assertEqual(first["asset_sha256"], second["asset_sha256"])
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        verified = self.verifier.verify(json.loads(self.operation.read_text()), first, self.bundle)
        self.assertEqual(verified["status"], "PASS")
        self.assertEqual(verified["asset_name"], ASSET_NAME)
        self.assertTrue(verified["current_bundle_matches_verified_operation"])
        self.assertTrue(verified["canonical_bundle_semantics_verified"])
        self.assertTrue(verified["zip_members_match_current_verified_bundle"])
        self.assertTrue(verified["private_key_material_absent"])
        self.assertTrue(verified["final_ga_attestation_verified"])
        self.assertTrue(verified["ga_eligible"])
        self.semantic_verify.assert_called_once_with(self.bundle, self.head)

    def test_canonical_semantic_failure_rejects_self_consistent_operation_and_zip(self) -> None:
        receipt, _ = self.build("semantic-failure")
        self.semantic_verify.side_effect = self.verifier._BUNDLE_VERIFIER.FinalAttestationBundleError(
            "synthetic semantic failure"
        )
        with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
            self.verifier.verify(json.loads(self.operation.read_text()), receipt, self.bundle)
        self.semantic_verify.assert_called_once_with(self.bundle, self.head)

    def test_bundle_byte_drift_after_operation_is_rejected(self) -> None:
        receipt, _ = self.build("drift-bundle")
        (self.bundle / "ga-policy.json").write_bytes(b'{"policy":"tampered"}\n')
        with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
            self.verifier.verify(json.loads(self.operation.read_text()), receipt, self.bundle)

    def test_zip_byte_drift_after_producer_receipt_is_rejected(self) -> None:
        receipt, asset = self.build("drift-zip")
        asset.write_bytes(asset.read_bytes() + b"tamper")
        with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
            self.verifier.verify(json.loads(self.operation.read_text()), receipt, self.bundle)

    def test_private_key_material_reintroduced_after_upstream_verification_is_rejected(self) -> None:
        receipt, _ = self.build("private")
        (self.bundle / "unexpected.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nNOPE\n")
        with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
            self.verifier.verify(json.loads(self.operation.read_text()), receipt, self.bundle)

    def test_execution_head_drift_is_rejected(self) -> None:
        receipt, _ = self.build("head")
        operation = json.loads(self.operation.read_text())
        operation["execution_head"] = "b" * 40
        with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
            self.verifier.verify(operation, receipt, self.bundle)

    def test_source_freezes_public_bundle_name_and_deterministic_zip_metadata(self) -> None:
        text = BUILDER.read_text(encoding="utf-8") + "\n" + VERIFIER.read_text(encoding="utf-8")
        self.assertIn(ASSET_NAME, text)
        self.assertIn("ZIP_STORED", text)
        self.assertIn("1980, 1, 1, 0, 0, 0", text)
        self.assertIn("materialized_tree_sha256", text)
        self.assertIn("PRIVATE_MARKERS", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
