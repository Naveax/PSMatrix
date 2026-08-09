import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-provision-selfhosted.yml"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "hyperv-provisioning-workflow-contract.json"
)
RUNNER_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "runner-contract.json"


class WindowsAuthorityHyperVProvisioningWorkflowTests(unittest.TestCase):
    def test_contract_freezes_secret_and_mutation_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-hyperv-provisioning-workflow-contract",
        )
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertTrue(value["dispatch"]["manual_only"])
        self.assertEqual(
            value["protected_secrets"]["required"],
            [
                "PSMATRIX_WPS40_ADMIN_PASSWORD",
                "PSMATRIX_WPS50_ADMIN_PASSWORD",
                "PSMATRIX_WPS51_ADMIN_PASSWORD",
            ],
        )
        self.assertEqual(
            value["protected_secrets"]["forbidden"],
            [
                "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
                "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY",
                "PSMATRIX_RELEASE_PRIVATE_KEY",
            ],
        )
        self.assertEqual(value["product_identity"]["wheel_install_mode"], "offline-no-index-no-deps")
        self.assertEqual(
            value["prerequisites"]["provisioning_manifest_kind"],
            "psmatrix.windows-lab-media",
        )
        self.assertEqual(value["prerequisites"]["exact_runtime_count"], 3)
        self.assertEqual(value["prerequisites"]["hyper_v_generation"], 2)
        self.assertEqual(value["prerequisites"]["clean_checkpoint_name"], "psmatrix-clean")
        self.assertEqual(value["prerequisites"]["materialization_status"], "PASS")
        self.assertEqual(value["prerequisites"]["product_loader_validation"], "PASS")
        self.assertEqual(value["prerequisites"]["operation_package_status"], "READY_FOR_WINDOWS_HOST")
        self.assertEqual(value["prerequisites"]["operation_package_binding_status"], "PASS")
        self.assertTrue(
            value["prerequisites"][
                "operation_package_must_match_current_provisioning_manifest_sha256"
            ]
        )
        self.assertFalse(value["prerequisites"]["stale_rc2_operation_package_used"])
        self.assertTrue(value["execution"]["product_lab_plan_required"])
        self.assertTrue(value["execution"]["product_lab_provision_required"])
        self.assertTrue(value["execution"]["exact_release_source_passed_to_provisioner"])
        self.assertTrue(value["execution"]["canonical_vm_set_reverified_with_hyper_v"])
        self.assertEqual(value["execution"]["exact_vm_count"], 3)
        self.assertEqual(value["execution"]["exact_clean_checkpoint_count"], 3)
        self.assertEqual(
            value["success"]["status"],
            "VM_SET_PROVISIONED_OS_MEASUREMENT_PENDING",
        )
        self.assertFalse(value["success"]["actual_os_identity_measured"])
        self.assertTrue(value["success"]["creates_virtual_machines"])
        self.assertTrue(value["success"]["creates_checkpoints"])
        self.assertFalse(value["success"]["runs_authoritative_campaign"])
        self.assertFalse(value["success"]["authoritative"])
        self.assertFalse(value["success"]["ga_eligible"])
        self.assertFalse(value["artifact_policy"]["protected_detailed_report_uploaded"])
        self.assertTrue(value["artifact_policy"]["sanitized_status_only"])

    def test_workflow_uses_only_provisioning_passwords_and_product_cli(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-provision-selfhosted",
            "workflow_dispatch:",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "PSMATRIX_WPS40_ADMIN_PASSWORD: ${{ secrets.PSMATRIX_WPS40_ADMIN_PASSWORD }}",
            "PSMATRIX_WPS50_ADMIN_PASSWORD: ${{ secrets.PSMATRIX_WPS50_ADMIN_PASSWORD }}",
            "PSMATRIX_WPS51_ADMIN_PASSWORD: ${{ secrets.PSMATRIX_WPS51_ADMIN_PASSWORD }}",
            "path: control",
            "path: release-source",
            "ref: ${{ inputs.release_commit }}",
            "psmatrix.windows-lab-media",
            "psmatrix.windows-authority-provisioning-manifest-materialization",
            "operation.provisioning_manifest.sha256",
            "Operation package is bound to another provisioning manifest SHA-256",
            "pip install --no-index --no-deps --force-reinstall",
            "python -m psmatrix.cli lab plan",
            "python -m psmatrix.cli lab provision",
            "--source-root $env:PSMATRIX_PROVISION_RELEASE_SOURCE",
            "config\\hyperv-host-endpoint.json",
            "Get-VM -Name $vmName",
            "Get-VMSnapshot -VM $vm",
            "VM_SET_PROVISIONED_OS_MEASUREMENT_PENDING",
            "actual_os_identity_measured = $false",
            "creates_virtual_machines = $true",
            "creates_checkpoints = $true",
            "runs_authoritative_campaign = $false",
            "protected_detailed_report_uploaded = $false",
            "Upload sanitized provisioning status only",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY: ${{ secrets.PSMATRIX_WINDOWS_LAB_PRIVATE_KEY }}",
            "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY: ${{ secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY }}",
            "PSMATRIX_RELEASE_PRIVATE_KEY: ${{ secrets.PSMATRIX_RELEASE_PRIVATE_KEY }}",
            "Invoke-PSMatrixAuthoritativeWindowsGA.ps1",
            "--iterations",
            "authoritative = $true",
            "ga_eligible = $true",
            "path: ${{ env.PSMATRIX_PROVISION_RUN_ROOT }}",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_runner_contract_separates_provisioning_and_campaign_secrets(self) -> None:
        value = json.loads(RUNNER_CONTRACT.read_text(encoding="utf-8"))
        controller = value["controller"]
        self.assertEqual(
            controller["provisioning_required_protected_secrets"],
            [
                "PSMATRIX_WPS40_ADMIN_PASSWORD",
                "PSMATRIX_WPS50_ADMIN_PASSWORD",
                "PSMATRIX_WPS51_ADMIN_PASSWORD",
            ],
        )
        self.assertEqual(
            controller["campaign_required_protected_secrets"],
            ["PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"],
        )
        self.assertTrue(controller["provisioning_must_not_receive_campaign_signing_secrets"])
        self.assertTrue(controller["infrastructure_preflight_requires_no_private_key_secret"])
        self.assertTrue(value["provisioning"]["creates_virtual_machines"])
        self.assertTrue(value["provisioning"]["creates_checkpoints"])
        self.assertFalse(value["provisioning"]["runs_authoritative_campaign"])
        self.assertFalse(value["provisioning"]["authoritative"])
        self.assertFalse(value["provisioning"]["ga_eligible"])


if __name__ == "__main__":
    unittest.main()
