from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "run_public_auth_evidence_content_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("public_auth_evidence_content_operation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicAuthEvidenceContentOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_exact_cross_gate_binding_is_accepted(self) -> None:
        binding = {
            "schema": 1,
            "kind": "psmatrix.public-auth-cross-gate-content-binding",
            "version": "2.0.0",
            "status": "PASS",
            "covered_gates": ["public-oauth", "public-mtls"],
            "run_ids": {"public-oauth": 101, "public-mtls": 102},
            "artifact_ids": {"public-oauth": 201, "public-mtls": 202},
            "cross_gate_semantics_verified": True,
            "content_semantics_verified": True,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }
        self.module.validate_binding(binding)

    def test_duplicate_run_or_artifact_identity_fails_closed(self) -> None:
        base = {
            "schema": 1,
            "kind": "psmatrix.public-auth-cross-gate-content-binding",
            "version": "2.0.0",
            "status": "PASS",
            "covered_gates": ["public-oauth", "public-mtls"],
            "run_ids": {"public-oauth": 101, "public-mtls": 101},
            "artifact_ids": {"public-oauth": 201, "public-mtls": 202},
            "cross_gate_semantics_verified": True,
            "content_semantics_verified": True,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }
        with self.assertRaises(self.module.PublicAuthEvidenceContentOperationError):
            self.module.validate_binding(base)
        base["run_ids"] = {"public-oauth": 101, "public-mtls": 102}
        base["artifact_ids"] = {"public-oauth": 201, "public-mtls": 201}
        with self.assertRaises(self.module.PublicAuthEvidenceContentOperationError):
            self.module.validate_binding(base)

    def test_workspace_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(self.module.PublicAuthEvidenceContentOperationError):
            self.module._external_workspace(ROOT / ".tmp-public-auth-content")

    def test_source_materializes_both_gates_and_uses_cross_gate_binder(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('("public-oauth", "public-mtls")', text)
        self.assertIn("materialize_verified_evidence_artifact.py", text)
        self.assertIn("bind_public_auth_evidence_content.py", text)
        self.assertIn("both_materialized_trees_verified", text)
        self.assertIn("cross_gate_semantics_verified", text)
        self.assertIn("final_ga_evaluator_invoked", text)
        self.assertIn("ga_eligible", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
