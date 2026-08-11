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

    def support(self, **values: Path | None) -> dict[str, Path | None]:
        result = {flag: None for flag in self.module.SUPPORT_DESTS}
        mapping = {
            "active_lock": "--active-lock",
            "run_verification": "--run-verification",
            "lab_public_key": "--lab-public-key",
            "release_public_key": "--release-public-key",
            "protected_release_public_key": "--protected-release-public-key",
            "security_review_public_key": "--security-review-public-key",
        }
        for name, value in values.items():
            result[mapping[name]] = value
        return result

    def test_no_support_is_required_for_self_contained_gates(self) -> None:
        for gate in ("validation-summary", "complete-runtime-matrix", "disaster-recovery"):
            self.assertEqual(self.module.build_verifier_args(gate, self.support()), [])

    def test_signed_release_requires_exact_named_support_files(self) -> None:
        values = self.module.build_verifier_args(
            "signed-release",
            self.support(active_lock=self.root / "lock.json", run_verification=self.root / "release-run.json"),
        )
        self.assertEqual(values[0], "--active-lock")
        self.assertEqual(values[2], "--run-verification")
        self.assertEqual(Path(values[1]), (self.root / "lock.json").resolve())

    def test_vulnerability_scan_requires_release_and_review_authorities(self) -> None:
        values = self.module.build_verifier_args(
            "vulnerability-scan",
            self.support(release_public_key=self.root / "release.pem", security_review_public_key=self.root / "review.pem"),
        )
        self.assertEqual(values[0], "--release-public-key")
        self.assertEqual(values[2], "--security-review-public-key")

    def test_missing_or_irrelevant_support_fails_closed(self) -> None:
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module.build_verifier_args("external-otlp", self.support())
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module.build_verifier_args("validation-summary", self.support(release_public_key=self.root / "release.pem"))

    def test_public_auth_gates_are_not_accepted_by_single_gate_operator(self) -> None:
        for gate in ("public-oauth", "public-mtls"):
            with self.assertRaises(self.module.SingleEvidenceContentOperationError):
                self.module.build_verifier_args(gate, self.support())

    def test_workspace_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(self.module.SingleEvidenceContentOperationError):
            self.module._external_workspace(ROOT / ".tmp-evidence-content")

    def test_source_delegates_to_frozen_materializer_and_binder_with_safe_argv_encoding(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("materialize_verified_evidence_artifact.py", text)
        self.assertIn("bind_verified_evidence_content.py", text)
        self.assertIn('f"--verifier-arg={token}"', text)
        self.assertIn('parser.add_argument("--active-lock"', text)
        self.assertIn('parser.add_argument("--security-review-public-key"', text)
        self.assertIn("api_artifact_origin_verified", text)
        self.assertIn("content_semantics_verified", text)
        self.assertIn("final_ga_evaluator_invoked", text)
        self.assertIn("ga_eligible", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
