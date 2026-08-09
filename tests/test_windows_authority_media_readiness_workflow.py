import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-media-readiness-selfhosted.yml"
HANDOFF_PREFLIGHT = (
    ROOT
    / ".github"
    / "workflows"
    / "ga-windows-authority-provisioning-handoff-source-preflight.yml"
)
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "media-readiness-workflow-contract.json"
)


class WindowsAuthorityMediaReadinessWorkflowTests(unittest.TestCase):
    def test_contract_freezes_selection_materialization_boundary(self) -> None:
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
        selection = value["selection_materialization"]
        self.assertEqual(
            selection["kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertEqual(
            selection["path"], "config/windows-authority-media-selection.json"
        )
        self.assertFalse(selection["direct_hyper_v_input"])
        self.assertTrue(selection["requires_separate_provisioning_profile"])
        self.assertEqual(selection["next_output_kind"], "psmatrix.windows-lab-media")
        self.assertEqual(
            value["result_classes"],
            [
                "EXTERNAL_MEDIA_INCOMPLETE",
                "READY_FOR_OPERATOR_SELECTION",
                "READY_FOR_PROVISIONING_MANIFEST_MATERIALIZATION",
                "FAIL",
            ],
        )
        self.assertFalse(value["safety"]["writes_provisioning_manifest"])
        self.assertFalse(value["safety"]["creates_virtual_machines"])
        self.assertFalse(value["safety"]["creates_checkpoints"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_workflow_writes_selection_to_distinct_path(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "name: production-ga-windows-authority-media-readiness-selfhosted",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "media\\release\\2.0.0rc3",
            "media\\external",
            "RELEASE_CLOSURE_READY",
            "Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "config\\windows-authority-media-selection.json",
            "-OutputPath $selectionOutput",
            "psmatrix.windows-authority-media-selection-materialization",
            "ready_for_provisioning_manifest_materialization",
            "provisioning_manifest_materialized = $false",
            "ready_for_hyper_v_provisioning = $false",
            "READY_FOR_PROVISIONING_MANIFEST_MATERIALIZATION",
            "READY_FOR_OPERATOR_SELECTION",
            "EXTERNAL_MEDIA_INCOMPLETE",
            "windows-authority-rc3-media-readiness",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)

        for forbidden in (
            "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1",
            "build_windows_authority_provisioning_manifest.py",
            "Join-Path $HOME 'Downloads'",
            "Join-Path $HOME 'Desktop'",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "authoritative = $true",
            "ga_eligible = $true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_handoff_source_preflight_is_pinned_to_trusted_self_hosted_runner(self) -> None:
        text = HANDOFF_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn(
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            text,
        )
        self.assertIn("Expected NAVEAX runner", text)
        self.assertIn("runner_assignment=PASS", text)
        self.assertNotIn("runs-on: ubuntu-latest", text)
        self.assertNotIn("runs-on: windows-latest", text)

    def test_failure_evidence_is_initialized_before_ga_root_validation(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        initialize = text.index("PSMATRIX_MEDIA_READINESS_EVIDENCE=$evidence")
        ga_root_validation = text.index("PSMATRIX_WINDOWS_GA_ROOT is missing")
        self.assertLess(initialize, ga_root_validation)


if __name__ == "__main__":
    unittest.main()
