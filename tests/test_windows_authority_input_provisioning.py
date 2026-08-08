import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Get-PSMatrixWindowsAuthorityInputPlan.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "input-provisioning-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityInputProvisioningTests(unittest.TestCase):
    def test_contract_freezes_real_input_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-input-provisioning-contract",
        )
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(value["isolated_release_root"], "media/release/2.0.0rc3")
        self.assertEqual(value["isolated_operation_root"], "operation/2.0.0rc3")
        self.assertEqual(
            value["required_runtime_ids"],
            [
                "windows-powershell-4.0",
                "windows-powershell-5.0",
                "windows-powershell-5.1",
            ],
        )
        self.assertEqual(
            value["canonical_hyper_v"]["clean_snapshot_name"],
            "psmatrix-clean",
        )
        self.assertEqual(value["canonical_hyper_v"]["generation"], 2)
        self.assertEqual(
            value["release_authority"]["protected_release_intake_status"],
            "RELEASE_CLOSURE_READY",
        )
        self.assertEqual(
            value["release_authority"]["release_public_key_source"],
            "verified-protected-release-bundle",
        )
        self.assertFalse(value["release_authority"]["release_public_key_secret_required"])
        self.assertTrue(value["media_authority"]["complete"])
        self.assertTrue(value["media_authority"]["ready_for_hyper_v_provisioning"])
        self.assertEqual(value["operation_authority"]["package_status"], "READY_FOR_WINDOWS_HOST")
        self.assertEqual(value["operation_authority"]["binding_status"], "PASS")
        self.assertTrue(value["operation_authority"]["ready_for_release_artifact_recovery"])
        self.assertFalse(value["operation_authority"]["stale_rc2_operation_package_used"])
        self.assertFalse(value["inventory"]["mutates_hyper_v"])
        self.assertFalse(value["inventory"]["creates_validator_inputs"])
        self.assertFalse(value["inventory"]["searches_broad_download_locations"])
        self.assertFalse(value["authority"]["inventory_is_authoritative_evidence"])
        self.assertFalse(value["authority"]["inventory_is_ga_eligible"])
        self.assertTrue(value["authority"]["placeholder_promotion_forbidden"])
        self.assertFalse(value["completion"]["ga_eligible"])

    def test_inventory_is_read_only_rc3_bound_and_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "[ValidatePattern('^[0-9a-f]{40}$')]",
            "$releaseVersion = '2.0.0rc3'",
            "Test-IsAdministrator",
            "git -C $source rev-parse HEAD",
            "git -C $source status --porcelain",
            "Import-Module Hyper-V",
            "Get-Service -Name vmms",
            "Get-VMHost",
            "Get-VM -ErrorAction Stop",
            "Get-VMSnapshot",
            "Get-ExactFixturePackDigest",
            "load_fixture_pack",
            "media\\release\\2.0.0rc3",
            "operation\\2.0.0rc3",
            "psmatrix-2.0.0rc3-release.json",
            "psmatrix-2.0.0rc3-release-public.pem",
            "RELEASE_CLOSURE_READY",
            "windows-lab-media.json",
            "ready_for_hyper_v_provisioning",
            "READY_FOR_WINDOWS_HOST",
            "ready_for_release_artifact_recovery",
            "PSMatrix-Windows-PowerShell-4.0",
            "PSMatrix-Windows-PowerShell-5.0",
            "PSMatrix-Windows-PowerShell-5.1",
            "psmatrix-clean",
            "release_public_key_source = 'verified-protected-release-bundle'",
            "release_public_key_secret_required = $false",
            "ready_for_input_materialization",
            "ready_to_dispatch_infrastructure_preflight",
            "authoritative = $false",
            "ga_eligible = $false",
            "does not create VMs, checkpoints, signed release artifacts",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Join-Path $root 'release'",
            "PSMATRIX_RELEASE_PUBLIC_KEY",
            "New-VM ",
            "Remove-VM ",
            "Checkpoint-VM ",
            "Restore-VMSnapshot ",
            "New-VMSwitch ",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "Invoke-Expression",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_source_preflight_tracks_input_provisioning_contract(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "scripts/ga/Get-PSMatrixWindowsAuthorityInputPlan.ps1",
            "tests/test_windows_authority_input_provisioning.py",
            "Parse Windows authority PowerShell scripts",
            "tests.test_windows_authority_input_provisioning",
            "input_provisioning_contract",
            "input_provisioning_powershell_parse",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
