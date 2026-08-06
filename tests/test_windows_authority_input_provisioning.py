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
        self.assertFalse(value["inventory"]["mutates_hyper_v"])
        self.assertFalse(value["inventory"]["creates_validator_inputs"])
        self.assertFalse(value["authority"]["inventory_is_authoritative_evidence"])
        self.assertFalse(value["authority"]["inventory_is_ga_eligible"])
        self.assertTrue(value["authority"]["placeholder_promotion_forbidden"])
        self.assertFalse(value["completion"]["ga_eligible"])

    def test_inventory_is_read_only_and_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "[ValidatePattern('^[0-9a-f]{40}$')]",
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
            "PSMatrix-Windows-PowerShell-4.0",
            "PSMatrix-Windows-PowerShell-5.0",
            "PSMatrix-Windows-PowerShell-5.1",
            "psmatrix-clean",
            "ready_to_dispatch_infrastructure_preflight",
            "authoritative = $false",
            "ga_eligible = $false",
            "does not create VMs, checkpoints, signed release artifacts",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "New-VM ",
            "Remove-VM ",
            "Checkpoint-VM ",
            "Restore-VMSnapshot ",
            "New-VMSwitch ",
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
