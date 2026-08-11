from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "run_single_evidence_content_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("single_evidence_content_operation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SingleEvidenceContentOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ("lock.json", "release-run.json", "windows.pem", "release.pem", "review.pem"):
            (self.root / name).write_text("public support\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_no_extra_args_are_required_for_self_contained_gates(self) -> None:
        for gate in ("validation-summary", "complete-runtime-matrix", "disaster-recovery"):
            self.assertEqual(self.module.validate_verifier_args(gate, []), [])

    def test_signed_release_requires_exact_two_support_flags(self) -> None:
        values = self.module.validate_verifier_args(
            "signed-release",
            ["--run-verification", str(self.root / "release-run.json"), "--active-lock", str(self.root / "lock.json")],
        )
        self.assertEqual(values[0], "--active-lock")
        self.assertEqual(values[2], "--run-verification")
        self.assertEqual(Path(values[1]), (self.root / "lock.json").resolve())

    def test_vulnerability_scan_requires_release_and_review_authorities(self) -> None:
        values = self.module.validate_verifier_args(
            "vulnerability-scan",
            ["--security-review-public-key", str(self.root / "review.pem"), "--release-public-key", str(self.root / "release.pem")],
        )
        self.assertEqual(values[0], "--release-public-key")
        self.assertEqual(values[2], "--security-review-public-key")

    def test_unknown_or_duplicate_flags_fail_closed(self) -> None:
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module.validate_verifier_args("external-otlp", ["--anything", str(self.root / "release.pem")])
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module.validate_verifier_args("signed-release", ["--active-lock", str(self.root / "lock.json"), "--active-lock", str(self.root / "lock.json")])

    def test_public_auth_gates_are_not_accepted_by_single_gate_operator(self) -> None:
        for gate in ("public-oauth", "public-mtls"):
            with self.assertRaises(self.module.SingleEvidenceContentOperationError):
                self.module.validate_verifier_args(gate, [])

    def test_workspace_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module._external_workspace(ROOT / ".tmp-evidence-content")

    def test_source_delegates_to_frozen_materializer_and_binder(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("materialize_verified_evidence_artifact.py", text)
        self.assertIn("bind_verified_evidence_content.py", text)
        self.assertIn("api_artifact_origin_verified", text)
        self.assertIn("content_semantics_verified", text)
        self.assertIn("final_ga_evaluator_invoked", text)
        self.assertIn("ga_eligible", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
