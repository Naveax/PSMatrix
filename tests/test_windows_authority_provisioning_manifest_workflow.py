import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (
    ROOT
    / ".github"
    / "workflows"
    / "ga-windows-authority-provisioning-manifest-selfhosted.yml"
)
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "provisioning-manifest-workflow-contract.json"
)


class WindowsAuthorityProvisioningManifestWorkflowTests(unittest.TestCase):
    def test_contract_freezes_real_product_manifest_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-provisioning-manifest-workflow-contract",
        )
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertEqual(
            value["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        self.assertTrue(value["product_identity"]["current_control_checkout_required"])
        self.assertTrue(value["product_identity"]["exact_rc3_product_checkout_required"])
        self.assertTrue(value["product_identity"]["product_loader_validation_required"])
        prerequisites = value["prerequisites"]
        self.assertEqual(
            prerequisites["selection_materialization_kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertEqual(
            prerequisites["selection_materialization_path"],
            "config/windows-authority-media-selection.json",
        )
        self.assertEqual(
            prerequisites["provisioning_profile_kind"],
            "psmatrix.windows-authority-provisioning-profile",
        )
        output = value["output"]
        self.assertEqual(output["manifest_kind"], "psmatrix.windows-lab-media")
        self.assertEqual(output["materialization_status"], "PASS")
        self.assertEqual(output["product_loader_validation"], "PASS")
        self.assertEqual(output["exact_runtime_count"], 3)
        self.assertEqual(output["hyper_v_generation"], 2)
        self.assertEqual(output["clean_checkpoint_name"], "psmatrix-clean")
        self.assertTrue(output["complete"])
        self.assertTrue(output["ready_for_hyper_v_provisioning"])
        self.assertFalse(output["actual_os_identity_measured"])
        self.assertFalse(output["authoritative"])
        self.assertFalse(output["ga_eligible"])

    def test_workflow_materializes_then_revalidates_final_bytes(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "name: production-ga-windows-authority-provisioning-manifest-selfhosted",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "path: control",
            "path: release-source",
            "ref: ${{ inputs.release_commit }}",
            "config\\windows-authority-media-selection.json",
            "config\\windows-lab-provisioning-profile.json",
            "config\\windows-lab-media.json",
            "windows-authority-provisioning-manifest-materialization.json",
            "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1",
            "-WriteProfileTemplate",
            "-RequireComplete",
            "psmatrix.windows-lab-media",
            "WindowsLabManifest.load",
            "operation_package_handoff_validation",
            "READY_FOR_OPERATION_PACKAGE",
            "actual_os_identity_measured = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "authoritative = $false",
            "ga_eligible = $false",
            "windows-authority-rc3-provisioning-manifest-status",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
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

        initialize = text.index("PSMATRIX_PROVISIONING_MANIFEST_EVIDENCE=$evidence")
        ga_root = text.index("PSMATRIX_WINDOWS_GA_ROOT is missing")
        materialize = text.index("Materialize product-loader-valid RC3 provisioning manifest")
        normalize = text.index("Normalize operation-package handoff metadata and revalidate final bytes")
        enforce = text.index("Enforce real provisioning manifest closure and emit non-secret status")
        self.assertLess(initialize, ga_root)
        self.assertLess(materialize, normalize)
        self.assertLess(normalize, enforce)


if __name__ == "__main__":
    unittest.main()
