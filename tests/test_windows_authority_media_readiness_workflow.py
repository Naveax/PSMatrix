import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-media-readiness-selfhosted.yml"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "media-readiness-workflow-contract.json"
)


class WindowsAuthorityMediaReadinessWorkflowTests(unittest.TestCase):
    def test_contract_freezes_isolated_media_readiness_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-media-readiness-workflow-contract",
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
            value["search_roots"],
            ["media/release/2.0.0rc3", "media/external"],
        )
        self.assertEqual(
            value["prerequisite"]["protected_release_intake_status"],
            "RELEASE_CLOSURE_READY",
        )
        self.assertFalse(value["prerequisite"]["release_authority_rotated"])
        self.assertFalse(value["prerequisite"]["stale_rc2_operation_package_used"])
        for key in (
            "exactly_two_search_roots",
            "broad_downloads_search_forbidden",
            "release_bound_candidates_must_match_signed_release_manifest",
            "iso_inspection_is_read_only",
            "iso_dismount_is_mandatory",
            "selection_inventory_sha256_must_match",
            "operator_review_required_before_final_manifest",
            "final_manifest_written_only_when_complete",
        ):
            self.assertTrue(value["rules"][key])
        self.assertEqual(
            value["result_classes"],
            [
                "EXTERNAL_MEDIA_INCOMPLETE",
                "READY_FOR_OPERATOR_SELECTION",
                "READY_FOR_HYPER_V_PROVISIONING",
                "FAIL",
            ],
        )
        for key in (
            "downloads_files",
            "opens_secret_bundles",
            "uploads_media_inventory",
            "uploads_candidate_files",
            "creates_virtual_machines",
            "creates_checkpoints",
            "restores_snapshots",
            "writes_endpoint_manifests",
            "writes_image_manifests",
            "authoritative",
            "ga_eligible",
        ):
            self.assertFalse(value["safety"][key])
        self.assertTrue(value["safety"]["uploads_non_secret_status_only"])

    def test_workflow_uses_only_isolated_ga_media_roots(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-media-readiness-selfhosted",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "PSMATRIX_WINDOWS_GA_ROOT: ${{ vars.PSMATRIX_WINDOWS_GA_ROOT }}",
            "RELEASE_COMMIT: ${{ inputs.release_commit }}",
            "INSPECT_ISO_IMAGES: ${{ inputs.inspect_iso_images }}",
            "media\\release\\2.0.0rc3",
            "media\\external",
            "RELEASE_CLOSURE_READY",
            "Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "SearchRoot = @($env:PSMATRIX_MEDIA_RELEASE_ROOT, $env:PSMATRIX_MEDIA_EXTERNAL_ROOT)",
            "Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "-WriteSelectionTemplate",
            "EXTERNAL_MEDIA_INCOMPLETE",
            "READY_FOR_OPERATOR_SELECTION",
            "READY_FOR_HYPER_V_PROVISIONING",
            "broad_downloads_search_used = $false",
            "opens_secret_bundles = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "authoritative = $false",
            "ga_eligible = $false",
            "windows-authority-rc3-media-readiness",
            "path: ${{ runner.temp }}/psmatrix-windows-authority-media-readiness-evidence",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Join-Path $HOME 'Downloads'",
            "Join-Path $HOME 'Desktop'",
            "C:\\ISO",
            "C:\\Installers",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "authoritative = $true",
            "ga_eligible = $true",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_failure_evidence_is_initialized_before_ga_root_validation(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        initialize = text.index("PSMATRIX_MEDIA_READINESS_EVIDENCE=$evidence")
        ga_root_validation = text.index("PSMATRIX_WINDOWS_GA_ROOT is missing")
        self.assertLess(initialize, ga_root_validation)


if __name__ == "__main__":
    unittest.main()
