from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_evidence_content_operator_plan.py"


def load_module():
    spec = importlib.util.spec_from_file_location("evidence_content_operator_plan", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalEvidenceContentOperatorPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.head = "a" * 40
        self.rows = []
        for index, gate in enumerate(self.module.REQUIRED_GATES, start=1):
            self.rows.append({"gate": gate, "run_id": 1000 + index, "artifact_id": 2000 + index, "artifact": f"artifact-{gate}", "verified": True})
        self.api = {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": self.head,
            "verified_gate_count": 11,
            "gates": self.rows,
        }
        (self.root / "active-lock.json").write_text(json.dumps({"schema": 1, "kind": "psmatrix.windows-authority-final-release-staging-lock", "version": "2.0.0", "promotion_state": "READY_FOR_EXACT_REPOSITORY_COMMIT"}), encoding="utf-8")
        signed_row = next(row for row in self.rows if row["gate"] == "signed-release")
        (self.root / "release-run.json").write_text(json.dumps({"schema": 1, "kind": "psmatrix.final-release-signing-run-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": self.head, "run_id": signed_row["run_id"], "signed_release_run_verified": True}), encoding="utf-8")
        for name, data in (("windows.pem", b"WINDOWS PUBLIC\n"), ("release.pem", b"RELEASE PUBLIC\n"), ("review.pem", b"REVIEW PUBLIC\n")):
            (self.root / name).write_bytes(data)
        self.manifest_path = self.root / "support.json"
        self.manifest = {
            "schema": 1,
            "kind": "psmatrix.final-ga-evidence-content-support-files",
            "version": "2.0.0",
            "files": {
                "active_lock": "active-lock.json",
                "release_signing_run_verification": "release-run.json",
                "windows_lab_public_key": "windows.pem",
                "release_public_key": "release.pem",
                "security_review_public_key": "review.pem",
            },
        }
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_plan_passes_and_freezes_gate_specific_args(self) -> None:
        value = self.module.build(self.api, self.manifest, self.manifest_path)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["required_gate_count"], 11)
        self.assertEqual(value["single_artifact_gate_count"], 9)
        self.assertEqual(value["public_auth_gate_count"], 2)
        self.assertEqual(value["support_file_count"], 5)
        mapped = {row["gate"]: row for row in value["gates"]}
        self.assertIn("--active-lock", mapped["signed-release"]["verifier_args"])
        self.assertIn("--lab-public-key", mapped["authoritative-windows"]["verifier_args"])
        self.assertIn("--protected-release-public-key", mapped["key-rotation"]["verifier_args"])
        self.assertIn("--security-review-public-key", mapped["vulnerability-scan"]["verifier_args"])
        self.assertEqual(mapped["public-oauth"]["binding_mode"], "public-auth-cross-gate")
        self.assertFalse(value["content_closure_complete"])
        self.assertFalse(value["ga_eligible"])

    def test_release_run_must_match_signed_release_gate(self) -> None:
        path = self.root / "release-run.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["run_id"] += 99
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(self.module.EvidenceContentOperatorPlanError):
            self.module.build(self.api, self.manifest, self.manifest_path)

    def test_private_key_material_in_public_support_file_is_rejected(self) -> None:
        (self.root / "release.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-safe\n")
        with self.assertRaises(self.module.EvidenceContentOperatorPlanError):
            self.module.build(self.api, self.manifest, self.manifest_path)

    def test_gate_order_drift_fails_closed(self) -> None:
        self.api["gates"] = list(reversed(self.api["gates"]))
        with self.assertRaises(self.module.EvidenceContentOperatorPlanError):
            self.module.build(self.api, self.manifest, self.manifest_path)


if __name__ == "__main__":
    unittest.main()
