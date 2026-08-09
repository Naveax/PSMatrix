import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-operation-package-selfhosted.yml"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "operation-package-workflow-contract.json"
)


class WindowsAuthorityOperationPackageWorkflowTests(unittest.TestCase):
    def test_contract_requires_real_provisioning_handoff(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-operation-package-workflow-contract",
        )
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        prerequisites = value["prerequisites"]
        self.assertEqual(
            prerequisites["reviewed_release_lock_pack"], "03-authoritative-windows"
        )
        self.assertFalse(prerequisites["protected_release_intake_media_manifest_materialized"])
        self.assertFalse(prerequisites["protected_release_intake_operation_package_rebuilt"])
        self.assertEqual(
            prerequisites["reviewed_selection_kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertEqual(
            prerequisites["provisioning_manifest_kind"], "psmatrix.windows-lab-media"
        )
        self.assertTrue(prerequisites["provisioning_manifest_complete"])
        self.assertTrue(
            prerequisites["provisioning_manifest_ready_for_hyper_v_provisioning"]
        )
        self.assertEqual(prerequisites["provisioning_materialization_status"], "PASS")
        self.assertEqual(prerequisites["product_loader_validation"], "PASS")
        self.assertEqual(prerequisites["operation_package_handoff_validation"], "PASS")
        execution = value["execution"]
        for key in (
            "primary_build_required",
            "independent_rebuild_required",
            "byte_determinism_required",
            "builder_revalidates_selection_inventory_binding",
            "builder_revalidates_provisioning_manifest_sha256",
            "builder_revalidates_selection_sha256",
            "builder_revalidates_profile_sha256",
            "operation_package_binding_validator_required",
            "workflow_recomputes_provisioning_manifest_sha256",
            "workflow_recomputes_selection_sha256",
            "workflow_recomputes_profile_sha256",
            "workflow_recomputes_materialization_report_sha256",
            "workflow_recomputes_canonical_inventory_sha256",
            "workflow_requires_profile_under_ga_root",
            "workflow_revalidates_metadata_provisioning_binding",
            "workflow_revalidates_release_binding_against_disk",
            "ready_for_release_artifact_recovery_required",
            "run_attempt_scoped_output",
        ):
            self.assertTrue(execution[key])
        self.assertEqual(execution["binding_status_required"], "PASS")
        self.assertFalse(execution["overwrite_existing_output"])
        self.assertTrue(value["output"]["provisioning_manifest_binding_required"])
        self.assertEqual(
            value["output"]["provisioning_manifest_handoff_validation"], "PASS"
        )
        self.assertFalse(value["output"]["authoritative"])
        self.assertFalse(value["output"]["ga_eligible"])

    def test_workflow_builds_twice_and_binding_validator_remains_fail_closed(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "name: production-ga-windows-authority-operation-package-selfhosted",
            "workflow_dispatch:",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "run-{0}-attempt-{1}",
            "Current reviewed RC3 lock pack mismatch",
            "RELEASE_CLOSURE_READY",
            "Protected release intake contains stale downstream state",
            "windows-lab-media.json",
            "windows-authority-media-selection.json",
            "windows-authority-provisioning-manifest-materialization.json",
            "build_windows_authority_operation_package.py",
            "Build primary deterministic RC3 operation package",
            "Rebuild independently and enforce byte determinism",
            "Independent RC3 operation-package rebuild is not byte deterministic",
            "Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1",
            "READY_FOR_WINDOWS_HOST",
            "Provisioning profile is missing or escapes the protected GA root",
            "Operation metadata provisioning-manifest SHA-256 is stale",
            "Operation metadata reviewed-selection SHA-256 is stale",
            "Operation metadata provisioning-profile SHA-256 is stale",
            "Operation metadata provisioning-report SHA-256 is stale",
            "Operation metadata canonical-inventory SHA-256 is stale",
            "Release binding windows-lab-media SHA-256 differs from current disk state",
            "Release binding reviewed-selection SHA-256 differs from current disk state",
            "Release binding provisioning-profile SHA-256 differs from current disk state",
            "Release binding provisioning-report SHA-256 differs from current disk state",
            "Release binding canonical-inventory SHA-256 differs from current disk state",
            "provisioning_manifest_handoff_validation = 'PASS'",
            "ready_for_release_artifact_recovery",
            "release_manifest_matches_canonical",
            "embedded_release_artifacts_match_binding",
            "stale_rc2_operation_package_used -ne $false",
            "windows-authority-rc3-operation-package",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "psmatrix-2.0.0rc2-windows-authoritative-operation",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "authoritative = $true",
            "ga_eligible = $true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

        initialize = text.index("PSMATRIX_OPERATION_EVIDENCE=$evidence")
        ga_root_check = text.index("PSMATRIX_WINDOWS_GA_ROOT is missing")
        primary = text.index("Build primary deterministic RC3 operation package")
        rebuild = text.index("Rebuild independently and enforce byte determinism")
        binding = text.index("Verify operation package against canonical RC3 binding")
        enforce = text.index("Enforce operation-package closure and emit non-secret status")
        self.assertLess(initialize, ga_root_check)
        self.assertLess(primary, rebuild)
        self.assertLess(rebuild, binding)
        self.assertLess(binding, enforce)


if __name__ == "__main__":
    unittest.main()
