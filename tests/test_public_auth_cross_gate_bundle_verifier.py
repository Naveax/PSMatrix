from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_public_auth_cross_gate_bundles.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-deployment-evidence-producer-contract.json"
spec = importlib.util.spec_from_file_location("public_auth_cross", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class PublicAuthCrossGateBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _gate(self, root: Path, gate: str, endpoint: str):
        cfg = self.contract[gate]
        evidence_type = f"public-{gate}"
        assertions = {name: True for name in cfg["required_assertions"]}
        assertions.update({"endpoint": endpoint, "release_commit": self.contract["final_release_commit"], "release_manifest_sha256": "m" * 64, "release_wheel_sha256": "w" * 64})
        live = {"kind": "psmatrix.public-auth-live-report", "status": "PASS", "oauth": {"endpoint": "https://oauth.example.test"}, "mtls": {"endpoint": "https://mtls.example.test"}}
        write_json(root / "public-auth-live-report.json", live)
        live_sha = module.sha256_file(root / "public-auth-live-report.json")
        result = {"assertions": assertions, "artifacts": [{"name": "public-auth-live-report.json", "sha256": live_sha}]}
        write_json(root / cfg["proof_result"], result)
        write_json(root / cfg["proof"], {"placeholder": True})
        (root / cfg["public_key"]).write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        status = {"schema": 1, "kind": f"psmatrix.final-public-{gate}-producer-status", "status": "PASS", "version": "2.0.0", "endpoint": endpoint, "live_report_sha256": live_sha, "release_commit": self.contract["final_release_commit"], "release_manifest_sha256": "m" * 64, "release_wheel_sha256": "w" * 64, "deployment_public_key_sha256": module.sha256_file(root / cfg["public_key"]), "deployment_key_id": "deployment-key", "proof_verified": True, "deployment_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
        write_json(root / f"public-{gate}-producer-status.json", status)
        return evidence_type, result

    def test_oauth_and_mtls_cross_gate_closure_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-cross-") as temporary:
            base = Path(temporary)
            oauth_root = base / "oauth"; mtls_root = base / "mtls"; oauth_root.mkdir(); mtls_root.mkdir()
            oauth_type, oauth_result = self._gate(oauth_root, "oauth", "https://oauth.example.test")
            mtls_type, mtls_result = self._gate(mtls_root, "mtls", "https://mtls.example.test")
            def fake_verify(_envelope, *, expected_type, public_key):
                return {"valid": True, "result": oauth_result if expected_type == oauth_type else mtls_result}
            with patch.object(module, "verify_ga_proof", side_effect=fake_verify), patch.object(module, "public_key_id", return_value="deployment-key"):
                value = module.verify(oauth_root, mtls_root, self.contract)
            self.assertTrue(value["same_live_report_sha256"])
            self.assertTrue(value["different_public_endpoints"])
            self.assertTrue(value["same_deployment_authority"])
            self.assertFalse(value["ga_eligible"])

    def test_same_endpoint_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-cross-") as temporary:
            base = Path(temporary)
            oauth_root = base / "oauth"; mtls_root = base / "mtls"; oauth_root.mkdir(); mtls_root.mkdir()
            _, oauth_result = self._gate(oauth_root, "oauth", "https://same.example.test")
            _, mtls_result = self._gate(mtls_root, "mtls", "https://same.example.test")
            def fake_verify(_envelope, *, expected_type, public_key):
                return {"valid": True, "result": oauth_result if expected_type == "public-oauth" else mtls_result}
            with patch.object(module, "verify_ga_proof", side_effect=fake_verify), patch.object(module, "public_key_id", return_value="deployment-key"):
                with self.assertRaises(module.PublicAuthCrossGateError):
                    module.verify(oauth_root, mtls_root, self.contract)

    def test_authority_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-cross-") as temporary:
            base = Path(temporary)
            oauth_root = base / "oauth"; mtls_root = base / "mtls"; oauth_root.mkdir(); mtls_root.mkdir()
            _, oauth_result = self._gate(oauth_root, "oauth", "https://oauth.example.test")
            _, mtls_result = self._gate(mtls_root, "mtls", "https://mtls.example.test")
            (mtls_root / "deployment-public.pem").write_text("-----BEGIN PUBLIC KEY-----\ndifferent\n-----END PUBLIC KEY-----\n", encoding="utf-8")
            mtls_status = json.loads((mtls_root / "public-mtls-producer-status.json").read_text())
            mtls_status["deployment_public_key_sha256"] = module.sha256_file(mtls_root / "deployment-public.pem")
            write_json(mtls_root / "public-mtls-producer-status.json", mtls_status)
            def fake_verify(_envelope, *, expected_type, public_key):
                return {"valid": True, "result": oauth_result if expected_type == "public-oauth" else mtls_result}
            with patch.object(module, "verify_ga_proof", side_effect=fake_verify), patch.object(module, "public_key_id", return_value="deployment-key"):
                with self.assertRaises(module.PublicAuthCrossGateError):
                    module.verify(oauth_root, mtls_root, self.contract)


if __name__ == "__main__":
    unittest.main()
