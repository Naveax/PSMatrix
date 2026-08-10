import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-bootstrap-contract.json"
VALIDATOR = ROOT / "scripts" / "ga" / "validate_final_production_bootstrap.py"
EXECUTION = ROOT / "ga-packs" / "03-authoritative-windows" / "final-execution-control-contract.json"
LOCK_CONTROL = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-lock-signing-control-contract.json"
REVIEW_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-lock-review.yml"
PROMOTION_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-lock-promotion.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
BOOTSTRAP_PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-production-bootstrap-source-preflight.yml"
LEGACY_PHASE_PREFLIGHTS = [
    ".github/workflows/ga-windows-authority-provisioning-handoff-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-candidate-closure-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-candidate-closure-hardening-source-preflight.yml",
]


def _validator_module():
    spec = importlib.util.spec_from_file_location("psmatrix_final_production_bootstrap_test", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalProductionBootstrapContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.execution = json.loads(EXECUTION.read_text(encoding="utf-8"))
        cls.lock_control = json.loads(LOCK_CONTROL.read_text(encoding="utf-8"))
        cls.validator = _validator_module()

    def test_frozen_source_and_default_branch_identities_are_exact(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-production-bootstrap-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["execution_control_head"], "8d29ce6e957ab08206aba24e75f1324cafd46856")
        self.assertEqual(value["readiness_source_head"], "18eb9a7eed6fef807e709ce4377fd2709429066d")
        self.assertEqual(value["producer_source_anchor"], "89372d9432433237abdf677900093b399c4d0868")
        self.assertEqual(value["final_release_commit"], "02cef95d40cf524ce00f9d917188343dc49e6f2c")
        self.assertEqual(value["default_branch"], "main")

    def test_exact_nineteen_dispatch_paths_cover_execution_and_bootstrap(self) -> None:
        paths = self.contract["required_dispatch_workflow_paths"]
        self.assertEqual(len(paths), 19)
        self.assertEqual(len(paths), len(set(paths)))
        execution_paths = [item["path"] for item in self.execution["execution_sequence"]]
        self.assertEqual(len(execution_paths), 15)
        self.assertTrue(set(execution_paths) <= set(paths))
        self.assertEqual(
            set(paths) - set(execution_paths),
            {
                ".github/workflows/ga-windows-authority-rc4-release-authority-enrollment.yml",
                ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml",
                ".github/workflows/ga-windows-authority-final-release-lock-review.yml",
                ".github/workflows/ga-windows-authority-final-release-lock-promotion.yml",
            },
        )
        for relative in paths:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("workflow_dispatch:", text, relative)

    def test_legacy_phase_preflights_are_release_scoped_not_main_scoped(self) -> None:
        self.assertEqual(self.contract["legacy_phase_preflight_paths"], LEGACY_PHASE_PREFLIGHTS)
        self.assertEqual(len(LEGACY_PHASE_PREFLIGHTS), 4)
        for relative in LEGACY_PHASE_PREFLIGHTS:
            text = (ROOT / relative).read_text(encoding="utf-8")
            trigger = text.split("\nconcurrency:", 1)[0]
            self.assertIn("release/**", trigger, relative)
            self.assertNotIn("main", trigger, relative)

    def test_main_ci_defers_rc4_runtime_modules_on_final_source(self) -> None:
        text = CI_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "branches: [main]",
            "$packageVersion -ne '2.0.0rc4' -and $file.Name -like 'test_windows_authority_rc4_*.py'",
            "deferred_to_rc4_release_preflight=",
            "if ($packageVersion -eq '2.0.0' -and $releaseCandidateDeferred.Count -lt 1)",
            "release_candidate_runtime_policy=rc4-modules-deferred-on-non-rc4-source",
        ):
            self.assertIn(marker, text)
        self.assertIn("& python -m unittest $module -v", text)

    def test_post_publication_registration_gate_is_automatic_and_fail_closed(self) -> None:
        text = BOOTSTRAP_PREFLIGHT.read_text(encoding="utf-8")
        trigger = text.split("\nconcurrency:", 1)[0]
        self.assertIn('branches: ["final/2.0.0-production-bootstrap-controls", "main"]', trigger)
        self.assertIn("$env:GITHUB_EVENT_NAME -eq 'push' -and $env:GITHUB_REF -eq 'refs/heads/main'", text)
        self.assertIn("$args += '--require-default-branch-registration'", text)
        self.assertIn("post_publication_registration_enforced=", text)
        self.assertIn("post_publication_default_branch_registration_gate_required=true", text)

    def test_bootstrap_is_inserted_between_readiness_and_signed_release(self) -> None:
        self.assertEqual(
            self.contract["execution_insertion_point"],
            {"after_stage": "readiness", "before_stage": "signed-release"},
        )
        self.assertEqual([item["id"] for item in self.execution["execution_sequence"][:2]], ["readiness", "signed-release"])
        sequence = self.contract["bootstrap_sequence"]
        self.assertEqual(len(sequence), 10)
        self.assertEqual([item["step"] for item in sequence], list(range(1, 11)))
        self.assertEqual(sequence[0]["id"], "default-branch-publication")
        self.assertEqual(sequence[2]["id"], "production-readiness")
        self.assertEqual(sequence[5]["id"], "final-lock-review")
        self.assertEqual(sequence[7]["id"], "final-lock-promotion")
        self.assertEqual(sequence[8]["id"], "exact-lock-authority-repository-commit")
        self.assertEqual(sequence[-1]["id"], "active-lock-authority-verification")

    def test_active_repository_targets_match_lock_signing_contract_and_are_absent(self) -> None:
        self.assertEqual(self.contract["active_repository_targets"], self.lock_control["repository_targets"])
        for relative in self.contract["active_repository_targets"].values():
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_bootstrap_requirements_are_fail_closed(self) -> None:
        requirements = self.contract["requirements"]
        for key in (
            "default_branch_publication_required_before_any_production_dispatch",
            "all_required_dispatch_workflow_paths_must_exist_on_default_branch",
            "post_publication_default_branch_registration_gate_required",
            "legacy_phase_preflights_must_not_trigger_default_branch",
            "main_ci_must_defer_rc4_runtime_modules_on_non_rc4_source",
            "readiness_source_preflight_success_required",
            "production_readiness_pass_required_before_lock_bootstrap",
            "review_and_promotion_runs_must_share_exact_control_head",
            "review_run_must_be_successful_workflow_dispatch",
            "promotion_run_must_be_successful_workflow_dispatch",
            "exactly_one_nonexpired_review_artifact_required",
            "human_reviewed_draft_sha256_required",
            "human_reviewed_public_key_sha256_required",
            "exact_repository_commit_required_before_signing",
            "active_lock_and_public_key_must_both_exist_before_signed_release",
        ):
            self.assertIs(requirements[key], True, key)
        self.assertEqual(requirements["reviewed_sha256_format"], "^[0-9a-f]{64}$")
        for key in (
            "promotion_workflow_may_mutate_repository",
            "automatic_production_dispatch_allowed_from_source_preflight",
            "automatic_merge_allowed",
            "ga_eligibility_before_full_evidence_and_final_attestation",
        ):
            self.assertIs(requirements[key], False, key)

    def test_review_and_promotion_workflows_freeze_provenance_and_human_digests(self) -> None:
        review = REVIEW_WORKFLOW.read_text(encoding="utf-8")
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "run.get('event') != 'workflow_dispatch'",
            "run.get('status') != 'completed'",
            "run.get('conclusion') != 'success'",
            "expected exactly one non-expired",
            "DRAFT_REQUIRES_HUMAN_REVIEW",
            "READY_FOR_HUMAN_REVIEW",
        ):
            self.assertIn(item, review)
        for item in (
            "reviewed_draft_sha256",
            "reviewed_public_key_sha256",
            "^[0-9a-f]{64}$",
            "run.get('event') != 'workflow_dispatch'",
            "(run.get('head_sha') or '').lower() != control_head",
            "READY_FOR_EXACT_REPOSITORY_COMMIT",
            "repository_mutated=false",
        ):
            self.assertIn(item, promotion)
        self.assertNotIn("git push", promotion.lower())

    def test_repository_validator_accepts_source_without_claiming_dispatch_readiness(self) -> None:
        result = self.validator.validate(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["required_dispatch_workflow_paths"], 19)
        self.assertEqual(result["legacy_phase_preflights"], 4)
        self.assertEqual(result["legacy_phase_preflight_default_branch_triggers"], 0)
        self.assertTrue(result["main_ci_rc4_phase_hygiene"])
        self.assertEqual(result["bootstrap_stages"], 10)
        self.assertEqual(result["control_source_paths"], 9)
        self.assertIsNone(result["default_branch_registration"])
        self.assertFalse(result["default_branch_dispatch_surface_ready"])
        self.assertFalse(result["production_readiness_executed"])
        self.assertFalse(result["active_final_lock_present"])
        self.assertFalse(result["signed_release_executed"])
        self.assertFalse(result["ga_eligible"])

    def test_default_branch_registration_is_reported_without_false_promotion(self) -> None:
        fake = {
            "default_branch": "main",
            "required": 19,
            "present": 0,
            "missing": list(self.contract["required_dispatch_workflow_paths"]),
            "ready": False,
        }
        with mock.patch.object(self.validator, "inspect_default_branch_registration", return_value=fake):
            result = self.validator.validate(ROOT, inspect_default_branch=True)
            self.assertEqual(result["default_branch_registration"]["present"], 0)
            self.assertFalse(result["default_branch_dispatch_surface_ready"])
            with self.assertRaises(self.validator.ProductionBootstrapError):
                self.validator.validate(ROOT, require_default_branch_registration=True)

    def test_source_layer_is_exact_nine_paths_and_cannot_claim_production(self) -> None:
        source = self.contract["control_source"]
        self.assertIs(source["runtime_source_changes_allowed"], False)
        self.assertEqual(
            set(source["changed_path_allowlist"]),
            {
                ".github/workflows/ci.yml",
                ".github/workflows/ga-final-production-bootstrap-source-preflight.yml",
                ".github/workflows/ga-windows-authority-provisioning-handoff-source-preflight.yml",
                ".github/workflows/ga-windows-authority-rc4-source-preflight.yml",
                ".github/workflows/ga-windows-authority-rc4-candidate-closure-source-preflight.yml",
                ".github/workflows/ga-windows-authority-rc4-candidate-closure-hardening-source-preflight.yml",
                "ga-packs/03-authoritative-windows/final-production-bootstrap-contract.json",
                "scripts/ga/validate_final_production_bootstrap.py",
                "tests/test_final_production_bootstrap_contract.py",
            },
        )
        self.assertEqual(len(source["changed_path_allowlist"]), 9)
        for key, value in self.contract["preparation_state"].items():
            self.assertIs(value, False, key)


if __name__ == "__main__":
    unittest.main()
