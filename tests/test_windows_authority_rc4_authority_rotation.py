import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "psmatrix" / "__init__.py"
RC3_LOCK = ROOT / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"
FINAL_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-source-promotion-contract.json"
ENROLL_SCRIPT = ROOT / "scripts" / "ga" / "enroll_windows_authority_release_authority.py"
LOCK_DRAFT_SCRIPT = ROOT / "scripts" / "ga" / "build_windows_authority_release_lock_draft.py"
SOURCE_PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"
ENROLL_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-authority-enrollment.yml"
STAGING_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-staging-candidate-selfhosted.yml"
LOCK_REVIEW_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-lock-review.yml"


class WindowsAuthorityRC4AuthorityRotationTests(unittest.TestCase):
    def test_rc4_is_a_new_candidate_and_rc3_lock_remains_frozen(self) -> None:
        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        init_text = INIT.read_text(encoding="utf-8")
        match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
        self.assertIsNotNone(match)
        expected_current = "2.0.0" if FINAL_CONTRACT.is_file() else "2.0.0rc4"
        self.assertEqual(project["project"]["version"], expected_current)
        self.assertEqual(match.group(1), expected_current)

        lock = json.loads(RC3_LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["version"], "2.0.0rc3")
        self.assertEqual(lock["release_commit"], "34e87c60885001f8dd11744b8bf194a59e51bd1f")
        self.assertEqual(
            lock["release_public_key"]["sha256"],
            "ebe3041f5e24b3d9fc21d50a3a33585e399ae505271fdf8900a0b49750188b83",
        )
        self.assertFalse(lock["safety"]["release_authority_rotation_allowed"])

    def test_enrollment_script_rotates_only_for_new_candidate_and_never_generates_key(self) -> None:
        text = ENROLL_SCRIPT.read_text(encoding="utf-8")
        required = (
            '"lost_previous_private_authority"',
            '"READY_FOR_PUBLIC_AUTHORITY_REVIEW"',
            '"private_key_published": False',
            '"private_key_copied_to_output": False',
            '"release_artifacts_signed": False',
            '"release_lock_written": False',
            '"release_authority_rotated_in_existing_candidate": False',
            '"new_candidate_authority_rotation_requested": True',
            '"requires_public_authority_review": True',
            '"requires_new_candidate_release_lock": True',
            '"authoritative": False',
            '"ga_eligible": False',
            "candidate_commit must be a full 40-character lowercase Git SHA",
            "must not be stored inside the repository",
            "must not silently reuse the previous release authority",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "generate_ed25519_keypair",
            '"genpkey"',
            "create_release_manifest",
            "sign_windows_authority_release_candidate",
            '"release_artifacts_signed": True',
            '"release_lock_written": True',
            '"authoritative": True',
            '"ga_eligible": True',
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_rc4_source_preflight_tracks_every_rotation_control_and_scans_tracked_pem_material(self) -> None:
        text = SOURCE_PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-rc4-source-preflight",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            ".github/workflows/ga-windows-authority-rc4-release-authority-enrollment.yml",
            ".github/workflows/ga-windows-authority-rc4-staging-candidate-selfhosted.yml",
            ".github/workflows/ga-windows-authority-rc4-release-lock-review.yml",
            "scripts/ga/enroll_windows_authority_release_authority.py",
            "scripts/ga/build_windows_authority_release_candidate.py",
            "scripts/ga/build_windows_authority_release_lock_draft.py",
            "tests/test_windows_authority_release_candidate_builder.py",
            "tests/test_windows_authority_rc4_authority_rotation.py",
            "python -m py_compile",
            "tests.test_windows_authority_rc4_authority_rotation",
            "git ls-files",
            "Tracked private-key PEM material detected",
            "repository_private_authority_absence=PASS",
            "rc3_lock_mutated=false",
            "private_key_generated=false",
            "active_rc4_lock_written=false",
            "release_artifacts_signed=false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("production-ga-release-signing", text)

    def test_protected_enrollment_workflow_limits_private_key_to_one_step(self) -> None:
        text = ENROLL_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "environment: production-ga-release-signing",
            "runs-on: ubuntu-latest",
            "candidate_commit must equal exact workflow control head",
            "Materialize protected private key only in hosted temp",
            "RELEASE_PRIVATE_KEY: ${{ secrets.PSMATRIX_RELEASE_PRIVATE_KEY }}",
            "Remove protected private key",
            "shred -u",
            "private_key_free_rc4_authority_enrollment=PASS",
            "psmatrix-2.0.0rc4-release-authority-enrollment",
            "lost_previous_private_authority",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        self.assertEqual(text.count("secrets.PSMATRIX_RELEASE_PRIVATE_KEY"), 1)
        self.assertLess(
            text.index("Materialize protected private key only in hosted temp"),
            text.index("secrets.PSMATRIX_RELEASE_PRIVATE_KEY"),
        )
        for value in (
            "generate_ed25519_keypair",
            "New-VM",
            "Checkpoint-VM",
            "windows-authority-rc4-locked-staging",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_unsigned_staging_is_self_hosted_unlocked_and_non_secret(self) -> None:
        text = STAGING_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "Expected NAVEAX Windows runner",
            "release_commit must equal exact workflow control head",
            "2.0.0rc4",
            "build_windows_authority_release_candidate.py",
            "Expected exactly six RC4 release artifacts",
            "rc4_unsigned_prelock_staging=PASS",
            "release_lock_written=false",
            "release_artifacts_signed=false",
            "windows-authority-rc4-unlocked-staging-candidate",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "production-ga-release-signing",
            "secrets.",
            "rc4-release-lock.json",
            "sign_windows_authority_release_candidate.py",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_lock_draft_builder_cannot_activate_sign_or_drop_source_run_provenance(self) -> None:
        text = LOCK_DRAFT_SCRIPT.read_text(encoding="utf-8")
        required = (
            '"DRAFT_REQUIRES_HUMAN_REVIEW"',
            '"active_lock_written": False',
            '"release_artifacts_signed": False',
            '"review_required": True',
            '"existing_candidate_mutated": False',
            '"new_candidate": True',
            '"lost_previous_private_authority"',
            '"release_authority_rotation_allowed": False',
            '"private_key_in_repository_allowed": False',
            '"sign_without_exact_hash_match_allowed": False',
            'output / "rc4-release-lock.review-draft.json"',
            "Private-key material found in review bundle",
            "enrollment_run_id",
            "staging_run_id",
            '"source_runs": source_runs',
            '"control_head": candidate_commit',
            '"workflow": "production-ga-windows-authority-rc4-release-authority-enrollment"',
            '"artifact": f"psmatrix-{_VERSION}-release-authority-enrollment"',
            '"workflow": "production-ga-windows-authority-rc4-staging-candidate-selfhosted"',
            '"artifact": "windows-authority-rc4-unlocked-staging-candidate"',
            "Enrollment and staging provenance must come from distinct workflow runs",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        for value in (
            "generate_ed25519_keypair",
            "sign_bytes",
            "create_release_manifest",
            '"active_lock_written": True',
            '"release_artifacts_signed": True',
            '"authoritative": True',
            '"ga_eligible": True',
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_lock_review_workflow_requires_same_exact_control_head_and_freezes_source_runs(self) -> None:
        text = LOCK_REVIEW_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "candidate_commit must equal the exact workflow control head",
            "Enrollment and staging run IDs must be distinct",
            "production-ga-windows-authority-rc4-release-authority-enrollment",
            "production-ga-windows-authority-rc4-staging-candidate-selfhosted",
            "psmatrix-2.0.0rc4-release-authority-enrollment",
            "windows-authority-rc4-unlocked-staging-candidate",
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            "build_windows_authority_release_lock_draft.py",
            "--enrollment-run-id $env:ENROLLMENT_RUN_ID",
            "--staging-run-id $env:STAGING_RUN_ID",
            "source_runs.control_head",
            "source_runs.authority_enrollment.run_id",
            "source_runs.authority_enrollment.workflow",
            "source_runs.authority_enrollment.artifact",
            "source_runs.unsigned_staging.run_id",
            "source_runs.unsigned_staging.workflow",
            "source_runs.unsigned_staging.artifact",
            "rc4_source_run_provenance=PASS",
            "DRAFT_REQUIRES_HUMAN_REVIEW",
            "Review workflow must not materialize an active rc4-release-lock.json",
            "rc4_release_lock_review_bundle=PASS",
            "active_lock_written=false",
            "release_artifacts_signed=false",
            "psmatrix-2.0.0rc4-release-lock-review",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        for value in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "secrets.",
            "production-ga-release-signing",
            "sign_windows_authority_release_candidate.py",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
