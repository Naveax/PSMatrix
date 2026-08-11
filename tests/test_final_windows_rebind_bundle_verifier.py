from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_windows_rebind_bundle.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-windows-evidence-rebind-control-contract.json"
spec = importlib.util.spec_from_file_location("rebind_bundle", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_json(path: Path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class FinalWindowsRebindBundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _bundle(self, root: Path):
        status = {"schema": 1, "kind": "psmatrix.windows-authority-final-windows-evidence-rebind-status", "status": self.contract["output"]["status"], "rc4_release_commit": self.contract["rc4_release"]["release_commit"], "final_release_commit": self.contract["final_release"]["release_commit"], "campaign_records_reused_byte_equivalent": True, "campaigns_reused_without_rerun": True, "final_signed_release_verified": True, "final_release_artifacts_signed": True, "authoritative_windows": True, "release_bound": True, "final_windows_evidence_rebound": True, "workers_contacted": False, "virtual_machines_created_or_mutated": False, "rc4_evidence_relabelled_as_final": False, "final_ga_evaluator_invoked": False, "ga_eligible": False}
        write_json(root / "final-windows-evidence-rebind-status.json", status)
        write_json(root / "windows-release-binding.json", {"placeholder": True})
        write_json(root / "windows-authoritative.dsse.json", {"placeholder": True})
        write_json(root / "authoritative-matrix-verification.json", {"valid": True, "release_bound": True, "campaign_count": 3})
        public = root / "lab-public.pem"
        public.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        return public

    def test_exact_final_rebind_passes_independent_matrix_verification(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-rebind-bundle-") as temporary:
            root = Path(temporary)
            public = self._bundle(root)
            binding = {"release_version": "2.0.0", "release_commit": self.contract["final_release"]["release_commit"], "binding_sha256": "x"}
            verified = {"valid": True, "release_bound": True, "campaign_count": 3, "release_binding": binding}
            with patch.object(module, "load_windows_release_binding", return_value=binding), patch.object(module, "verify_authoritative_matrix_attestation", return_value=verified):
                value = module.verify(root, self.contract, public)
            self.assertTrue(value["authoritative_matrix_cryptographically_verified"])
            self.assertTrue(value["final_windows_evidence_rebound"])
            self.assertFalse(value["ga_eligible"])

    def test_final_release_commit_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-rebind-bundle-") as temporary:
            root = Path(temporary)
            public = self._bundle(root)
            status = json.loads((root / "final-windows-evidence-rebind-status.json").read_text())
            status["final_release_commit"] = "b" * 40
            write_json(root / "final-windows-evidence-rebind-status.json", status)
            with self.assertRaises(module.FinalWindowsRebindBundleError):
                module.verify(root, self.contract, public)

    def test_invalid_independent_matrix_verification_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-rebind-bundle-") as temporary:
            root = Path(temporary)
            public = self._bundle(root)
            binding = {"release_version": "2.0.0", "release_commit": self.contract["final_release"]["release_commit"]}
            with patch.object(module, "load_windows_release_binding", return_value=binding), patch.object(module, "verify_authoritative_matrix_attestation", return_value={"valid": False}):
                with self.assertRaises(module.FinalWindowsRebindBundleError):
                    module.verify(root, self.contract, public)


if __name__ == "__main__":
    unittest.main()
