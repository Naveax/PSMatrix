import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Get-PSMatrixWindowsAuthorityMediaInventory.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "media-inventory-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityMediaInventoryTests(unittest.TestCase):
    def test_contract_freezes_read_only_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-media-inventory-contract",
        )
        self.assertEqual(value["mode"], "read-only-local-discovery")
        self.assertFalse(value["safety"]["downloads_files"])
        self.assertFalse(value["safety"]["creates_virtual_machines"])
        self.assertFalse(value["safety"]["creates_checkpoints"])
        self.assertFalse(value["safety"]["writes_validator_input_files"])
        self.assertFalse(value["safety"]["opens_bundle_contents"])
        self.assertTrue(value["safety"]["hashes_candidates"])
        self.assertTrue(value["safety"]["iso_dismount_is_mandatory"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_script_discovers_and_hashes_without_provisioning(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "[switch]$InspectIsoImages",
            "Get-FileHash",
            "Mount-DiskImage",
            "Dismount-DiskImage",
            "Get-WindowsImage",
            "windows-server-2012-r2-iso",
            "windows-server-2016-iso",
            "wmf-5.0-offline-package",
            "offline-python-x64-installer",
            "windows-workers-package",
            "controller-credential-bundle",
            "worker-signing-bundle",
            "classification_is_authoritative = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "writes_validator_inputs = $false",
            "authoritative = $false",
            "ga_eligible = $false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Remove-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "New-VHD",
            "Enable-WindowsOptionalFeature",
            "Invoke-Expression",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_source_preflight_tracks_media_inventory(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "scripts/ga/Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "tests/test_windows_authority_media_inventory.py",
            "Parse Windows authority PowerShell scripts",
            "tests.test_windows_authority_media_inventory",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
