import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-provision-selfhosted.yml"
RC3_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-provision-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-hyperv-provisioning-workflow-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


class WindowsAuthorityRC4HyperVProvisioningTests(unittest.TestCase):
    def test_contract_freezes_exact_three_vm_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-hyperv-provisioning-workflow-contract")
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["workflow"], "production-ga-windows-authority-rc4-provision-selfhosted")
        self.assertEqual(value["required_runner_labels"], ["self-hosted", "Windows", "X64", "psmatrix-hyperv"])
        self.assertEqual(
            value["vm_set"]["exact_runtime_ids"],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        )
        self.assertEqual(value["vm_set"]["vm_count"], 3)
        self.assertEqual(value["vm_set"]["generation"], 2)
        self.assertEqual(value["vm_set"]["checkpoint_name"], "psmatrix-clean")
        self.assertEqual(value["vm_set"]["checkpoint_count"], 3)
        self.assertEqual(value["output"]["status"], "VM_SET_PROVISIONED_OS_MEASUREMENT_PENDING")
        self.assertFalse(value["output"]["actual_os_identity_measured"])
        self.assertFalse(value["output"]["authoritative"])
        self.assertFalse(value["output"]["ga_eligible"])

    def test_contract_requires_exact_operation_and_active_lock_provenance(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        provenance = value["provenance"]
        for key in (
            "control_head_must_equal_workflow_sha",
            "active_rc4_release_lock_required",
            "active_lock_sha256_recomputed",
            "active_lock_release_commit_must_match",
            "reviewed_authority_rotation_required",
            "operation_root_is_run_and_attempt_scoped",
            "operation_metadata_active_lock_sha256_must_match",
            "operation_binding_ready_for_release_artifact_recovery",
            "operation_zip_sha256_recomputed",
            "provisioning_manifest_sha256_recomputed",
        ):
            self.assertTrue(provenance[key])
        self.assertFalse(provenance["release_authority_rotated_during_signing"])
        self.assertEqual(provenance["operation_metadata_status_required"], "READY_FOR_WINDOWS_HOST")
        self.assertEqual(provenance["operation_binding_status_required"], "PASS")
        self.assertTrue(value["product_execution"]["signed_release_wheel_installed_offline"])
        self.assertTrue(value["product_execution"]["exact_release_source_checkout_required"])
        self.assertTrue(value["product_execution"]["lab_plan_command_required"])
        self.assertTrue(value["product_execution"]["lab_provision_command_required"])
        self.assertFalse(value["safety"]["release_private_key_required"])
        self.assertFalse(value["safety"]["windows_lab_private_key_required"])
        self.assertFalse(value["safety"]["detailed_provisioning_report_uploaded"])

    def test_workflow_preserves_real_product_provisioning_entrypoint(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-rc4-provision-selfhosted",
            "environment: production-ga-windows-lab",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "control_head must equal the exact workflow control head",
            "operation\\2.0.0rc4\\run-{0}-attempt-{1}",
            "psmatrix-2.0.0rc4-windows-authoritative-operation-package.json",
            "psmatrix-2.0.0rc4-py3-none-any.whl",
            "rc4-release-lock.json",
            "lost_previous_private_authority",
            "release_authority_rotated_during_signing",
            "active_rc4_release_lock_sha256",
            "operation.release_lock.sha256",
            "operation.artifact.sha256",
            "python -m pip install --no-index --no-deps --force-reinstall",
            "python -m psmatrix.cli lab plan",
            "python -m psmatrix.cli lab provision",
            "Get-VM -Name",
            "Get-VMSnapshot -VM",
            "windows-powershell-4.0",
            "windows-powershell-5.0",
            "windows-powershell-5.1",
            "psmatrix-clean",
            "VM_SET_PROVISIONED_OS_MEASUREMENT_PENDING",
            "windows-authority-rc4-hyperv-provisioning-status",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)

    def test_workflow_is_fail_closed_and_does_not_smuggle_production_authority(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden in (
            "31189374564",
            "af4cef4a959941d6e35dc0b6ae88b183f35eadbb",
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
            "2.0.0rc3",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "actions/download-artifact",
            "operation-package.zip\n",
            "authoritative = $true",
            "ga_eligible = $true",
            "actual_os_identity_measured = $true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn("protected_detailed_report_uploaded = $false", text)
        self.assertIn("actual_os_identity_measured = $false", text)
        self.assertIn("runs_authoritative_campaign = $false", text)
        self.assertIn("authoritative = $false", text)
        self.assertIn("ga_eligible = $false", text)

    def test_historical_rc3_provisioning_workflow_remains_separate(self) -> None:
        text = RC3_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: production-ga-windows-authority-provision-selfhosted", text)
        self.assertIn("2.0.0rc3", text)
        self.assertIn("Provision exact RC3 Hyper-V VM set", text)
        self.assertNotIn("production-ga-windows-authority-rc4-provision-selfhosted", text)

    def test_source_preflight_tracks_rc4_hyperv_provisioning_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "ga-windows-authority-rc4-provision-selfhosted.yml",
            "rc4-hyperv-provisioning-workflow-contract.json",
            "tests/test_windows_authority_rc4_hyperv_provisioning.py",
            "tests.test_windows_authority_rc4_hyperv_provisioning",
            "rc4_hyperv_provisioning_contract=PASS",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
