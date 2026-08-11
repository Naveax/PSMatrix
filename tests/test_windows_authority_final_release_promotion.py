import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "psmatrix" / "__init__.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-source-promotion-contract.json"
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_final_release_candidate.py"
RC_BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_release_candidate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-staging-candidate-selfhosted.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-source-preflight.yml"
GA_EVALUATOR = ROOT / "src" / "psmatrix" / "ga.py"
FINAL_LOCK = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-lock.json"
FINAL_PUBLIC = ROOT / "release-assets" / "2.0.0" / "psmatrix-2.0.0-release-public.pem"
RC4_HEAD = "6019823c121752bb0660b306b95058d7a690172f"


class WindowsAuthorityFinalReleasePromotionTests(unittest.TestCase):
    def test_final_version_identity_is_exact_2_0_0(self) -> None:
        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        init_text = INIT.read_text(encoding="utf-8")
        match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(project["project"]["version"], "2.0.0")
        self.assertEqual(match.group(1), "2.0.0")

    def test_contract_freezes_separate_final_source_and_forbids_rc4_relabelling(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-final-release-source-promotion-contract")
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["from_version"], "2.0.0rc4")
        self.assertEqual(value["to_version"], "2.0.0")
        self.assertEqual(value["rc4_hardened_source_head"], RC4_HEAD)
        promotion = value["promotion"]
        self.assertTrue(promotion["separate_final_commit_required"])
        self.assertTrue(promotion["exact_rc4_anchor_must_be_ancestor"])
        self.assertFalse(promotion["rc4_evidence_may_be_relabelled_as_final"])
        self.assertEqual(promotion["runtime_source_change_allowlist"], ["src/psmatrix/__init__.py"])
        self.assertEqual(
            set(promotion["changed_path_allowlist"]),
            {
                ".github/workflows/ga-windows-authority-final-release-source-preflight.yml",
                ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml",
                "ga-packs/03-authoritative-windows/final-release-source-promotion-contract.json",
                "pyproject.toml",
                "scripts/ga/build_windows_authority_final_release_candidate.py",
                "src/psmatrix/__init__.py",
                "tests/test_windows_authority_final_release_promotion.py",
                "tests/test_windows_authority_rc4_authority_rotation.py",
                "tests/test_windows_authority_release_candidate_builder.py",
            },
        )
        state = value["candidate_state"]
        self.assertEqual(state["status"], "FINAL_RELEASE_SOURCE_PREPARATION")
        for field in (
            "release_artifacts_signed",
            "final_release_lock_written",
            "final_windows_evidence_rebound",
            "final_ga_evaluator_invoked",
            "authoritative",
            "ga_eligible",
        ):
            with self.subTest(field=field):
                self.assertFalse(state[field])

    def test_final_builder_is_exact_anchor_bound_reproducible_and_unsigned(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        required = (
            '_FINAL_VERSION = "2.0.0"',
            "final-release-source-promotion-contract.json",
            '"rc4_evidence_may_be_relabelled_as_final"',
            '"merge-base", "--is-ancestor"',
            '"diff", "--name-only"',
            "Final promotion changed-path closure mismatch",
            "Final promotion runtime-source closure mismatch",
            "Final release preparation must not contain an active final release lock",
            "Final release preparation must not contain an active final release public authority",
            "verify_reproducible_build",
            "build_reproducible_source",
            "build_windows_worker_package",
            "verify_windows_worker_package",
            "build_certification_kit",
            "verify_certification_kit",
            "build_provisioning_kit",
            "verify_provisioning_kit",
            '"SOURCE_DATE_EPOCH": "0"',
            '"PIP_NO_INDEX": "1"',
            '"kind": "psmatrix.windows-authority-final-release-candidate-staging"',
            '"status": "READY_FOR_FINAL_RELEASE_LOCK_REVIEW"',
            '"rc4_anchor_is_ancestor": True',
            '"release_artifacts_signed": False',
            '"final_release_lock_written": False',
            '"final_windows_evidence_rebound": False',
            '"final_ga_evaluator_invoked": False',
            '"rc4_evidence_relabelled_as_final": False',
            '"authoritative": False',
            '"ga_eligible": False',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "signing_private_key=",
            '"release_artifacts_signed": True',
            '"final_ga_evaluator_invoked": True',
            '"ga_eligible": True',
            "python -m psmatrix.cli ga evaluate",
            "New-VM",
            "Checkpoint-VM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_final_staging_workflow_is_non_secret_complete_scan_and_prelock_only(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-final-staging-candidate-selfhosted",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "Expected NAVEAX Windows runner",
            "release_commit must equal exact workflow control head",
            "fetch-depth: 0",
            "2.0.0",
            "build_windows_authority_final_release_candidate.py",
            "scan_private_key_material_streaming.py",
            "size_limit_applied",
            "Expected exactly six final release artifacts",
            "final_unsigned_prelock_staging=PASS",
            "final_release_lock_written=false",
            "release_artifacts_signed=false",
            "final_windows_evidence_rebound=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
            "windows-authority-final-unlocked-staging-candidate",
            "windows-authority-final-staging-private-scan",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "production-ga-release-signing",
            "secrets.",
            "sign_windows_authority_release_candidate.py",
            "python -m psmatrix.cli ga evaluate",
            "New-VM",
            "Checkpoint-VM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_final_source_preflight_tracks_complete_final_boundary(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-windows-authority-final-release-source-preflight",
            'branches: ["final/**"]',
            "fetch-depth: 0",
            "final-release-source-promotion-contract.json",
            "build_windows_authority_final_release_candidate.py",
            "ga-windows-authority-final-staging-candidate-selfhosted.yml",
            "tests/test_windows_authority_final_release_promotion.py",
            "tests.test_windows_authority_final_release_promotion",
            "tests.test_windows_authority_release_candidate_builder",
            "tests.test_windows_authority_rc4_authority_rotation",
            "scan_private_key_material_streaming.py",
            "final_release_source_contract=PASS",
            "final_release_artifacts_signed=false",
            "final_windows_evidence_rebound=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)

    def test_historical_rc_builder_remains_candidate_only(self) -> None:
        text = RC_BUILDER.read_text(encoding="utf-8")
        self.assertIn('_RC = re.compile(r"^2\\.0\\.0rc[0-9]+$")', text)
        self.assertIn("Windows Authority staging requires a 2.0.0rcN version", text)
        self.assertNotIn("READY_FOR_FINAL_RELEASE_LOCK_REVIEW", text)

    def test_final_ga_evaluator_is_not_invoked_and_still_requires_final_version(self) -> None:
        text = GA_EVALUATOR.read_text(encoding="utf-8")
        self.assertIn('_GA_VERSION = "2.0.0"', text)
        self.assertIn('raise GAGateError("Signed release is not the final 2.0.0 release")', text)
        self.assertIn('raise GAGateError("Authoritative Windows matrix is not bound to the signed release")', text)

    def test_preparation_branch_has_no_active_final_lock_or_public_authority(self) -> None:
        self.assertFalse(FINAL_LOCK.exists())
        self.assertFalse(FINAL_PUBLIC.exists())


if __name__ == "__main__":
    unittest.main()
