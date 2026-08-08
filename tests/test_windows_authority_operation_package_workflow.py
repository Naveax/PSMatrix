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
    def test_contract_freezes_operation_package_workflow_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-operation-package-workflow-contract",
        )
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertEqual(
            value["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        self.assertEqual(
            value["prerequisites"]["protected_release_intake_status"],
            "RELEASE_CLOSURE_READY",
        )
        self.assertEqual(
            value["prerequisites"]["canonical_release_authority_status"],
            "READY",
        )
        self.assertTrue(value["prerequisites"]["media_manifest_complete"])
        self.assertTrue(value["prerequisites"]["media_manifest_ready_for_hyper_v_provisioning"])
        for key in (
            "primary_build_required",
            "independent_rebuild_required",
            "byte_determinism_required",
            "operation_package_binding_validator_required",
            "ready_for_release_artifact_recovery_required",
            "run_attempt_scoped_output",
        ):
            self.assertTrue(value["execution"][key])
        self.assertEqual(value["execution"]["binding_status_required"], "PASS")
        self.assertFalse(value["execution"]["overwrite_existing_output"])
        self.assertEqual(value["output"]["package_status"], "READY_FOR_WINDOWS_HOST")
        self.assertEqual(value["output"]["production_ga_gate"], "INCOMPLETE")
        self.assertFalse(value["output"]["authoritative_campaign_executed"])
        self.assertFalse(value["output"]["authoritative"])
        self.assertFalse(value["output"]["ga_eligible"])
        for key in (
            "release_private_key_required",
            "windows_lab_private_key_required",
            "credential_bundle_contents_uploaded",
            "worker_signing_bundle_contents_uploaded",
            "operation_package_uploaded",
            "downloads_files",
            "uses_historical_rc2_operation_package",
            "creates_virtual_machines",
            "creates_checkpoints",
            "restores_snapshots",
            "runs_authoritative_campaign",
            "authoritative",
            "ga_eligible",
        ):
            self.assertFalse(value["safety"][key])
        self.assertTrue(value["safety"]["uploads_non_secret_status_only"])

    def test_workflow_builds_twice_then_requires_binding_pass(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-operation-package-selfhosted",
            "workflow_dispatch:",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "PSMATRIX_WINDOWS_GA_ROOT: ${{ vars.PSMATRIX_WINDOWS_GA_ROOT }}",
            "RELEASE_COMMIT: ${{ inputs.release_commit }}",
            "run-{0}-attempt-{1}",
            "RELEASE_CLOSURE_READY",
            "canonicalization.release_authority_status",
            "ready_for_hyper_v_provisioning",
            "build_windows_authority_operation_package.py",
            "Build primary deterministic RC3 operation package",
            "Rebuild independently and enforce byte determinism",
            "Independent RC3 operation-package rebuild is not byte deterministic",
            "Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1",
            "READY_FOR_WINDOWS_HOST",
            "ready_for_release_artifact_recovery",
            "release_manifest_matches_canonical",
            "embedded_release_artifacts_match_binding",
            "stale_rc2_operation_package_used -ne $false",
            "authoritative_campaign_executed -ne $false",
            "windows-authority-rc3-operation-package",
            "path: ${{ runner.temp }}/psmatrix-windows-authority-operation-package-evidence",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY",
            "Materialize protected release private key",
            "psmatrix-2.0.0rc2-windows-authoritative-operation",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "path: ${{ env.PSMATRIX_OPERATION_OUTPUT }}",
            "authoritative = $true",
            "ga_eligible = $true",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

        initialize = text.index("PSMATRIX_OPERATION_EVIDENCE=$evidence")
        ga_root_check = text.index("PSMATRIX_WINDOWS_GA_ROOT is missing")
        primary = text.index("Build primary deterministic RC3 operation package")
        rebuild = text.index("Rebuild independently and enforce byte determinism")
        binding = text.index("Verify operation package against canonical RC3 binding")
        enforce = text.index("Enforce operation-package closure and emit non-secret status")
        upload = text.index("Upload non-secret operation-package audit evidence")
        self.assertLess(initialize, ga_root_check)
        self.assertLess(primary, rebuild)
        self.assertLess(rebuild, binding)
        self.assertLess(binding, enforce)
        self.assertLess(enforce, upload)


if __name__ == "__main__":
    unittest.main()
