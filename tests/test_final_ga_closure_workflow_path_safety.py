from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-closure.yml"


class FinalGAClosureWorkflowPathSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_evidence_root_is_checked_before_canonicalization(self) -> None:
        self.assertNotIn('root="$(realpath "$PSMATRIX_FINAL_GA_ROOT")"', self.source)
        self.assertIn("raise SystemExit(f'{label} contains a symlink component')", self.source)
        self.assertIn("'final GA evidence root'", self.source)
        self.assertIn("'final GA policy'", self.source)

    def test_pre_secret_release_bootstrap_rejects_lexical_symlinks(self) -> None:
        self.assertNotIn("policy_path = Path(os.environ['PSMATRIX_FINAL_GA_POLICY']).resolve()", self.source)
        self.assertIn("def reject_symlink_components(path, label):", self.source)
        self.assertIn("candidate = reject_symlink_components(candidate, label)", self.source)
        self.assertIn("final_closure_release_bootstrap=PASS", self.source)

    def test_exact_wheel_reverification_does_not_restore_resolve_first_paths(self) -> None:
        self.assertNotIn("manifest = (base / record['manifest']).resolve()", self.source)
        self.assertNotIn("artifact_dir = (base / record['artifact_dir']).resolve()", self.source)
        self.assertNotIn("public = (base / authority['public_key']).resolve()", self.source)
        self.assertIn("exact final wheel runtime could not re-verify the protected release", self.source)

    def test_runtime_module_physical_containment_checks_are_preserved(self) -> None:
        self.assertIn("Path(psmatrix.__file__).resolve()", self.source)
        self.assertIn("path.relative_to(root)", self.source)
        self.assertIn("final closure runtime escaped exact signed wheel target", self.source)

    def test_post_sign_evidence_rejects_symlink_artifacts(self) -> None:
        self.assertIn("'private-key scan root'", self.source)
        self.assertIn("symlink found in closure artifact", self.source)
        self.assertIn("'final evidence root'", self.source)
        self.assertIn("required final closure artifact is a symlink", self.source)
        self.assertIn("final evidence inventory destination cannot be a symlink", self.source)


if __name__ == "__main__":
    unittest.main()
