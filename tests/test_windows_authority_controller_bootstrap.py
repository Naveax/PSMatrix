import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "ga" / "Initialize-PSMatrixWindowsAuthorityLab.ps1"
RC4_BOOTSTRAP = ROOT / "scripts" / "ga" / "Initialize-PSMatrixWindowsAuthorityLabRC4.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "controller-bootstrap-contract.json"
LEGACY_RC3_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "controller-bootstrap-contract-rc3.json"
BOOTSTRAP_DOC = ROOT / "ga-packs" / "03-authoritative-windows" / "CONTROLLER-BOOTSTRAP.md"
INFRA_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-infrastructure-preflight.yml"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityControllerBootstrapTests(unittest.TestCase):
    def test_current_contract_freezes_rc4_controller_and_authority_boundaries(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-controller-bootstrap-contract")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["legacy_contract"], "controller-bootstrap-contract-rc3.json")
        self.assertFalse(value["authority"]["bootstrap_is_authoritative_evidence"])
        self.assertFalse(value["authority"]["bootstrap_is_ga_eligible"])
        self.assertFalse(value["authority"]["actual_os_identity_measured_at_bootstrap"])
        self.assertTrue(value["controller"]["repository_and_ga_root_must_be_disjoint"])
        self.assertEqual(
            value["controller"]["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        self.assertEqual(
            value["controller"]["required_hyper_v_commands"],
            ["Get-VM", "Get-VMHost", "Get-VMSnapshot", "Restore-VMSnapshot", "Checkpoint-VM"],
        )
        self.assertEqual(value["controller"]["ga_root_variable"], "PSMATRIX_WINDOWS_GA_ROOT")
        self.assertEqual(
            value["controller"]["release_public_key_source"],
            "verified-protected-release-bundle",
        )
        self.assertFalse(value["controller"]["release_public_key_secret_required"])
        self.assertEqual(
            value["layout"]["required_directories"],
            [
                "media/release/2.0.0rc4",
                "media/external",
                "operation/2.0.0rc4",
                "provisioning/2.0.0rc4",
                "config",
                "trust-home",
            ],
        )
        self.assertEqual(
            value["required_runtime_ids"],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        )
        release = value["protected_inputs"]["release_intake"]
        self.assertEqual(release["schema"], 2)
        self.assertEqual(release["status"], "RELEASE_CLOSURE_READY")
        self.assertTrue(release["authority_rotation_reviewed"])
        self.assertEqual(release["authority_rotation_reason"], "lost_previous_private_authority")
        self.assertTrue(release["imported_release_root_must_match_current_ga_root"])
        self.assertTrue(release["selected_manifest_must_be_exact_current_release_manifest"])
        self.assertTrue(release["selected_manifest_sha256_must_match_current_file"])
        self.assertTrue(release["signed_wheel_required"])
        self.assertTrue(release["signed_wheel_sha256_and_size_must_match_release_manifest"])

        operation = value["protected_inputs"]["operation_package"]
        self.assertEqual(operation["metadata_status"], "READY_FOR_WINDOWS_HOST")
        self.assertEqual(operation["binding_status"], "PASS")
        self.assertEqual(
            operation["artifact_name"],
            "psmatrix-2.0.0rc4-windows-authoritative-operation.zip",
        )
        self.assertTrue(operation["artifact_file_required"])
        self.assertTrue(operation["artifact_sha256_matches_metadata"])
        self.assertTrue(operation["artifact_size_matches_metadata"])
        self.assertTrue(operation["release_binding_valid"])
        self.assertTrue(operation["release_manifest_matches_canonical"])
        self.assertTrue(operation["embedded_release_artifacts_match_binding"])
        self.assertEqual(operation["product_loader_validation"], "PASS")
        self.assertEqual(operation["operation_package_handoff_validation"], "PASS")

        materialization = value["protected_inputs"]["provisioning_manifest_materialization"]
        self.assertEqual(materialization["status"], "PASS")
        self.assertEqual(materialization["product_loader_validation"], "PASS")
        self.assertEqual(materialization["operation_package_handoff_validation"], "PASS")
        self.assertFalse(materialization["actual_os_identity_measured"])
        self.assertTrue(
            value["protected_inputs"]["host_endpoint"][
                "full_product_validation_owned_by_provisioning_workflow"
            ]
        )

        closure = value["dispatch_closure"]
        self.assertTrue(closure["required"])
        self.assertTrue(closure["same_release_commit_required"])
        self.assertTrue(closure["current_signed_release_manifest_matches_protected_intake"])
        self.assertTrue(closure["current_signed_wheel_matches_release_manifest"])
        self.assertTrue(closure["materialization_manifest_sha256_matches_current_media_manifest"])
        self.assertTrue(closure["operation_artifact_file_matches_metadata"])
        self.assertTrue(closure["operation_provisioning_sha256_matches_current_media_manifest"])
        self.assertTrue(closure["operation_selection_sha256_matches_materialization"])
        self.assertTrue(closure["operation_profile_sha256_matches_materialization"])
        self.assertTrue(closure["operation_materialization_report_sha256_matches_current_report"])
        self.assertTrue(closure["operation_binding_release_commit_matches_release_intake"])
        self.assertFalse(closure["file_presence_without_sha_closure_is_ready"])
        self.assertEqual(
            value["protected_configuration"]["required_provisioning_secret_names"],
            [
                "PSMATRIX_WPS40_ADMIN_PASSWORD",
                "PSMATRIX_WPS50_ADMIN_PASSWORD",
                "PSMATRIX_WPS51_ADMIN_PASSWORD",
            ],
        )
        self.assertTrue(
            value["protected_configuration"]["secret_values_must_not_be_persisted"]
        )
        self.assertEqual(
            value["completion"]["ready_field"],
            "ready_to_dispatch_rc4_provisioning",
        )
        self.assertEqual(
            value["completion"]["provisioning_workflow"],
            ".github/workflows/ga-windows-authority-rc4-provision-selfhosted.yml",
        )
        self.assertFalse(value["completion"]["authoritative"])
        self.assertFalse(value["completion"]["ga_eligible"])

    def test_legacy_rc3_contract_is_preserved_as_history(self) -> None:
        value = json.loads(LEGACY_RC3_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-controller-bootstrap-contract")
        self.assertEqual(value["layout"]["isolated_release_root"], "media/release/2.0.0rc3")
        self.assertEqual(value["layout"]["isolated_operation_root"], "operation/2.0.0rc3")
        self.assertFalse(value["layout"]["templates_are_evidence"])
        self.assertTrue(value["layout"]["templates_must_not_use_validator_filenames"])
        self.assertFalse(value["completion"]["ga_eligible"])

    def test_bootstrap_is_fail_closed_and_never_creates_fake_evidence(self) -> None:
        wrapper = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("Initialize-PSMatrixWindowsAuthorityLabRC4.ps1", wrapper)
        self.assertIn("@PSBoundParameters", wrapper)
        self.assertNotIn("2.0.0rc3", wrapper)
        self.assertNotIn("Invoke-Expression", wrapper)

        text = RC4_BOOTSTRAP.read_text(encoding="utf-8")
        required = (
            "[switch]$CreateLayout",
            "[switch]$RequireRunnerService",
            "[switch]$RequireReleaseInputs",
            "Test-IsAdministrator",
            "Win32_ComputerSystem",
            "VirtualizationFirmwareEnabled",
            "Microsoft-Hyper-V-All",
            "Import-Module Hyper-V",
            "Get-Service -Name vmms",
            "Get-VMSnapshot",
            "Restore-VMSnapshot",
            "Checkpoint-VM",
            "actions.runner.*PSMatrix*",
            "media\\release\\2.0.0rc4",
            "media\\external",
            "operation\\2.0.0rc4",
            "provisioning\\2.0.0rc4",
            "RELEASE_CLOSURE_READY",
            "windows-lab-media.json",
            "READY_FOR_WINDOWS_HOST",
            "ready_for_release_artifact_recovery",
            "ready_to_dispatch_rc4_provisioning",
            "release_public_key_source = 'verified-protected-release-bundle'",
            "release_public_key_secret_required = $false",
            "authority_level = 'local-controller-bootstrap'",
            "authoritative = $false",
            "ga_eligible = $false",
            "Bootstrap readiness is not infrastructure evidence",
            "GaRoot and the repository must be disjoint paths.",
            "psmatrix-2.0.0rc4-py3-none-any.whl",
            "psmatrix-2.0.0rc4-windows-authoritative-operation.zip",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn("2.0.0rc3", text)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", text)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PUBLIC_KEY", text)
        self.assertNotIn("protected secret: PSMATRIX_RELEASE_PUBLIC_KEY", text)
        self.assertNotIn("Join-Path $root 'release'", text)
        self.assertNotIn("Invoke-Expression", text)

    def test_current_bootstrap_documentation_tracks_rc4(self) -> None:
        text = BOOTSTRAP_DOC.read_text(encoding="utf-8")
        required = (
            "current RC4 controller bootstrap",
            "operator-selected infrastructure state",
            "media/release/2.0.0rc4",
            "media/external",
            "operation/2.0.0rc4",
            "provisioning/2.0.0rc4",
            "production-ga-windows-lab",
            "PSMATRIX_WINDOWS_GA_ROOT",
            "PSMATRIX_WPS40_ADMIN_PASSWORD",
            "PSMATRIX_WPS50_ADMIN_PASSWORD",
            "PSMATRIX_WPS51_ADMIN_PASSWORD",
            "ready_to_dispatch_rc4_provisioning",
            "ga-windows-authority-rc4-provision-selfhosted.yml",
            "controller-bootstrap-contract-rc3.json",
            "File presence is not enough.",
            "materialization-report SHA",
            "same release commit",
            "repository must be disjoint",
            "signed wheel",
            "operation ZIP",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn("2.0.0rc3", text)
        self.assertNotIn("PSMATRIX_RELEASE_PUBLIC_KEY", text)
        self.assertNotIn(r"D:\PSMatrix-Windows-GA", text)

    def test_infrastructure_workflow_initializes_evidence_before_checkouts(self) -> None:
        text = INFRA_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "Initialize fail-closed infrastructure evidence and exact paths",
            "PSMATRIX_WINDOWS_INFRA_EVIDENCE",
            "release_commit must contain exactly 40 lowercase hexadecimal characters",
            "Check out current infrastructure controls",
            "Check out exact RC3 release source",
            "path: control",
            "path: release-source",
            "Install exact signed RC3 controller package offline",
            "Revalidate exact operation package binding",
            "controller-context.json",
            "Record fail-closed infrastructure state",
            "preflight-failure.json",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertLess(
            text.index("Initialize fail-closed infrastructure evidence and exact paths"),
            text.index("Check out current infrastructure controls"),
        )
        self.assertNotIn("continue-on-error: true", text)
        self.assertNotIn("PSMATRIX_RELEASE_PUBLIC_KEY: ${{ secrets.PSMATRIX_RELEASE_PUBLIC_KEY }}", text)

    def test_source_preflight_tracks_bootstrap_contract(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "ga-packs/03-authoritative-windows/**",
            "scripts/ga/Initialize-PSMatrixWindowsAuthorityLab.ps1",
            "scripts/ga/Initialize-PSMatrixWindowsAuthorityLabRC4.ps1",
            "tests/test_windows_authority_controller_bootstrap.py",
            "tests/test_windows_lab_initializer_rc4.py",
            "Parse Windows authority PowerShell scripts",
            "tests.test_windows_authority_controller_bootstrap",
            "tests.test_windows_lab_initializer_rc4",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
