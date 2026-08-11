from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_key_rotation_bundle.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-operations-release-evidence-producer-contract.json"
spec = importlib.util.spec_from_file_location("key_rotation_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class KeyRotationBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _bundle(self, root: Path):
        cfg = self.contract["key_rotation"]
        write_json(root / cfg["proof"], {"placeholder": True})
        public = root / cfg["public_key"]
        public.write_text("-----BEGIN PUBLIC KEY-----\nrelease\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        protected = root / "protected-release-public.pem"
        protected.write_bytes(public.read_bytes())
        status = {"schema": 1, "kind": "psmatrix.final-key-rotation-producer-status", "status": "PASS", "version": "2.0.0", "release_key_id": "release-key", "release_public_key_sha256": module.sha256_file(public), "proof_verified": True, "bounded_temporary_trust_drill": True, "actual_release_authority_rotated": False, "release_private_key_copied_to_output": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
        write_json(root / "key-rotation-producer-status.json", status)
        assertions = {name: True for name in cfg["required_assertions"]}
        assertions["trust_generation"] = 2
        return protected, {"assertions": assertions}

    def test_exact_release_authority_bounded_rotation_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-key-rotation-") as temporary:
            root = Path(temporary)
            protected, result = self._bundle(root)
            with patch.object(module, "public_key_id", return_value="release-key"), patch.object(module, "verify_ga_proof", return_value={"valid": True, "key_ids": ["release-key"], "result": result}):
                value = module.verify(root, protected, self.contract)
            self.assertTrue(value["old_signature_rejected"])
            self.assertTrue(value["revocation_enforced"])
            self.assertEqual(value["trust_generation"], 2)
            self.assertFalse(value["actual_release_authority_rotated"])

    def test_release_authority_byte_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-key-rotation-") as temporary:
            root = Path(temporary)
            protected, result = self._bundle(root)
            protected.write_text("-----BEGIN PUBLIC KEY-----\ndrift\n-----END PUBLIC KEY-----\n", encoding="utf-8")
            with patch.object(module, "public_key_id", return_value="release-key"):
                with self.assertRaises(module.KeyRotationBundleError):
                    module.verify(root, protected, self.contract)

    def test_generation_one_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-key-rotation-") as temporary:
            root = Path(temporary)
            protected, result = self._bundle(root)
            result["assertions"]["trust_generation"] = 1
            with patch.object(module, "public_key_id", return_value="release-key"), patch.object(module, "verify_ga_proof", return_value={"valid": True, "key_ids": ["release-key"], "result": result}):
                with self.assertRaises(module.KeyRotationBundleError):
                    module.verify(root, protected, self.contract)


if __name__ == "__main__":
    unittest.main()
