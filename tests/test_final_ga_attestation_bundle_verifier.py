from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_attestation_bundle.py"
spec = importlib.util.spec_from_file_location("attestation_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def write_json(path: Path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def build_bundle(root: Path):
    write_json(root / "final-ga-attestation-status.json", {"kind": "psmatrix.final-ga-attestation-status", "version": "2.0.0", "status": "PASS", "execution_control_head": HEAD, "required_gate_count": 11, "all_required_gates_pass": True, "root_key_id": "root", "release_key_id": "release", "root_release_authorities_independent": True, "root_private_key_copied_to_output": False, "final_ga_attestation_written": True, "final_ga_attestation_verified": True, "ga_eligible": True})
    write_json(root / "final-ga-evaluator-candidate-status.json", {"status": "ALL_11_GATES_PASS_ROOT_SIGNING_PENDING", "gate_count": 11, "all_required_gates_pass": True})
    write_json(root / "final-ga-run-provenance.json", {"schema": 1, "kind": "psmatrix.final-ga-run-provenance", "execution_control_head": HEAD, "runs": {f"gate-{i}": {"run_id": 100 + i} for i in range(11)}})
    write_json(root / "ga-policy.json", {"status": "PASS"})
    write_json(root / "psmatrix-2.0.0-final-ga.dsse.json", {"payloadType": "test", "payload": "e30=", "signatures": []})
    write_json(root / "psmatrix-2.0.0-final-ga-verification.json", {"valid": True})
    (root / "psmatrix-2.0.0-ga-root-public.pem").write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    lines = []
    for path in sorted((item for item in root.iterdir() if item.is_file()), key=lambda item: item.name):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (root / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")


class FinalGAAttestationBundleVerifierTests(unittest.TestCase):
    def test_exact_bundle_with_independent_dsse_verification_passes(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-bundle-") as temporary:
            root = Path(temporary)
            build_bundle(root)
            with patch.object(module, "verify_ga_attestation", return_value={"valid": True}):
                value = module.verify(root, HEAD)
            self.assertTrue(value["dsse_cryptographically_verified"])
            self.assertTrue(value["final_ga_attestation_verified"])
            self.assertTrue(value["ga_eligible"])

    def test_execution_head_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-bundle-") as temporary:
            root = Path(temporary)
            build_bundle(root)
            with patch.object(module, "verify_ga_attestation", return_value={"valid": True}):
                with self.assertRaises(module.FinalAttestationBundleError):
                    module.verify(root, "b" * 40)

    def test_independent_dsse_failure_blocks_ga(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-bundle-") as temporary:
            root = Path(temporary)
            build_bundle(root)
            with patch.object(module, "verify_ga_attestation", return_value={"valid": False}):
                with self.assertRaises(module.FinalAttestationBundleError):
                    module.verify(root, HEAD)


if __name__ == "__main__":
    unittest.main()
