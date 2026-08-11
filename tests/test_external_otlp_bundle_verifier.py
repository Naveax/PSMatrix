from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_external_otlp_bundle.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-operations-release-evidence-producer-contract.json"
spec = importlib.util.spec_from_file_location("otlp_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class ExternalOTLPBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _bundle(self, root: Path):
        cfg = self.contract["external_otlp"]
        live = {"kind": "psmatrix.external-otlp-live-report", "status": "PASS", "secrets_in_report": False, "private_keys_in_report": False, "metrics_payload_in_report": False, "absolute_paths_in_report": False, "otlp": {"request_path": "/v1/metrics", "successful_exports": 2, "unauthenticated_status_code": 401}}
        write_json(root / cfg["live_report"], live)
        live_sha = module.sha256_file(root / cfg["live_report"])
        assertions = {name: True for name in cfg["required_assertions"]}
        assertions.update({"request_path": "/v1/metrics", "status_code": 204, "successful_exports": 2})
        result = {"assertions": assertions, "artifacts": [{"name": cfg["live_report"], "sha256": live_sha}]}
        write_json(root / cfg["proof_result"], result)
        write_json(root / cfg["proof"], {"placeholder": True})
        (root / cfg["public_key"]).write_text("-----BEGIN PUBLIC KEY-----\noperations\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        release_public = root / "release-public.pem"
        release_public.write_text("-----BEGIN PUBLIC KEY-----\nrelease\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        status = {"schema": 1, "kind": "psmatrix.final-external-otlp-producer-status", "status": "PASS", "version": "2.0.0", "proof_verified": True, "live_report_sha256": live_sha, "operations_key_id": "operations-key", "release_key_id": "release-key", "authorities_independent": True, "operations_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
        write_json(root / "external-otlp-producer-status.json", status)
        return release_public, result

    def test_exact_external_otlp_bundle_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bundle-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            def fake_id(path):
                return "release-key" if Path(path).name == "release-public.pem" else "operations-key"
            with patch.object(module, "verify_ga_proof", return_value={"valid": True, "result": result}), patch.object(module, "public_key_id", side_effect=fake_id):
                value = module.verify(root, release_public, self.contract)
            self.assertEqual(value["successful_exports"], 2)
            self.assertTrue(value["unauthenticated_rejection_verified"])
            self.assertTrue(value["operations_release_authorities_independent"])
            self.assertFalse(value["ga_eligible"])

    def test_missing_unauthenticated_rejection_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bundle-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            live_path = root / self.contract["external_otlp"]["live_report"]
            live = json.loads(live_path.read_text())
            live["otlp"]["unauthenticated_status_code"] = 200
            write_json(live_path, live)
            with self.assertRaises(module.ExternalOTLPBundleError):
                module.verify(root, release_public, self.contract)

    def test_same_operations_and_release_authority_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bundle-") as temporary:
            root = Path(temporary)
            release_public, result = self._bundle(root)
            with patch.object(module, "verify_ga_proof", return_value={"valid": True, "result": result}), patch.object(module, "public_key_id", return_value="same-key"):
                with self.assertRaises(module.ExternalOTLPBundleError):
                    module.verify(root, release_public, self.contract)


if __name__ == "__main__":
    unittest.main()
