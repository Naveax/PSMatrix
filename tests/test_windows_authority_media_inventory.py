import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCRIPT = ROOT / "scripts" / "ga" / "Get-PSMatrixWindowsAuthorityMediaInventory.ps1"
INVENTORY_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "media-inventory-contract.json"
MANIFEST_SCRIPT = ROOT / "scripts" / "ga" / "New-PSMatrixWindowsAuthorityMediaManifest.ps1"
MANIFEST_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "media-manifest-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityMediaInventoryTests(unittest.TestCase):
    def test_inventory_contract_freezes_read_only_boundary(self) -> None:
        value = json.loads(INVENTORY_CONTRACT.read_text(encoding="utf-8"))
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

    def test_inventory_script_discovers_without_provisioning(self) -> None:
        text = INVENTORY_SCRIPT.read_text(encoding="utf-8")
        for required in (
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
            "authoritative = $false",
            "ga_eligible = $false",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Remove-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "New-VHD",
            "Invoke-Expression",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_manifest_contract_is_reviewed_selection_not_provisioning_manifest(self) -> None:
        value = json.loads(MANIFEST_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-media-manifest-contract",
        )
        self.assertEqual(value["mode"], "reviewed-selection-materialization")
        self.assertEqual(
            value["manifest_kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertTrue(value["selection"]["inventory_sha256_must_match"])
        self.assertTrue(value["selection"]["iso_metadata_must_match_inventory"])
        self.assertTrue(
            value["selection"]["source_archive_must_match_signed_release_manifest"]
        )
        self.assertTrue(value["selection"]["placeholder_values_are_forbidden"])
        self.assertFalse(value["safety"]["writes_provisioning_manifest"])
        self.assertTrue(
            value["safety"]["writes_selection_materialization_only_when_complete"]
        )
        self.assertTrue(value["safety"]["atomic_selection_materialization_write"])
        self.assertFalse(
            value["completion"]["selection_materialization_is_provisioning_input"]
        )
        self.assertTrue(
            value["completion"]
            ["selection_materialization_ready_for_provisioning_manifest_materialization"]
        )
        self.assertEqual(
            value["completion"]["actual_provisioning_manifest_kind"],
            "psmatrix.windows-lab-media",
        )
        self.assertTrue(
            value["completion"]["actual_provisioning_manifest_requires_separate_profile"]
        )
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_selection_materializer_is_fail_closed_and_never_claims_hyper_v_readiness(self) -> None:
        text = MANIFEST_SCRIPT.read_text(encoding="utf-8")
        for required in (
            "Write-Utf8NoBomAtomic",
            "Get-FileHash",
            "$contract.manifest_kind",
            "inventory_sha256",
            "windows-lab-media-selection.example.json",
            "config\\windows-authority-media-selection.json",
            "Selected source archive is not listed in the signed release manifest.",
            "ISO image index",
            "if ($readyForSelectionMaterialization)",
            "final_manifest_written = $finalManifestWritten",
            "ready_for_selection_materialization = $readyForSelectionMaterialization",
            "ready_for_provisioning_manifest_materialization = $true",
            "provisioning_manifest_materialized = $false",
            "ready_for_hyper_v_provisioning = $false",
            "psmatrix.windows-lab-media from this exact reviewed selection",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "opens_secret_bundles = $false",
            "authoritative = $false",
            "ga_eligible = $false",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Remove-VM",
            "Start-VM",
            "Stop-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "New-VHD",
            "Expand-Archive",
            "Invoke-Expression",
            "ready_for_hyper_v_provisioning = $true",
            "Invoke the Hyper-V provisioning phase only with this exact manifest",
            "authoritative = $true",
            "ga_eligible = $true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_source_preflight_tracks_media_controls(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "scripts/ga/Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "scripts/ga/New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "tests/test_windows_authority_media_inventory.py",
            "tests.test_windows_authority_media_inventory",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
