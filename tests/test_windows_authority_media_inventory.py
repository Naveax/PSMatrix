import json
import shutil
import subprocess
import tempfile
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
            "$resolvedRoots.ToArray()",
            "$candidates.ToArray()",
            "$scanWarnings.ToArray()",
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
            "search_roots = @($resolvedRoots)",
            "candidates = @($candidates)",
            "warnings = @($scanWarnings)",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for runtime smoke")
    def test_script_executes_runtime_smoke(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)

        with tempfile.TemporaryDirectory(prefix="psmatrix-media-inventory-") as temporary:
            root = Path(temporary)
            source = root / "source"
            ga = root / "ga"
            search = root / "search"
            output = ga / "windows-authority-media-inventory.json"

            source.mkdir()
            ga.mkdir()
            search.mkdir()
            (search / "python-3.13.7-amd64.exe").write_bytes(
                b"psmatrix-media-inventory-runtime-smoke\n"
            )

            result = subprocess.run(
                [
                    str(pwsh),
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(SCRIPT),
                    "-SourceRoot",
                    str(source),
                    "-GaRoot",
                    str(ga),
                    "-SearchRoot",
                    str(search),
                    "-OutputPath",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            self.assertTrue(output.is_file())

            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS_PARTIAL")
            self.assertEqual(report["candidate_count"], 1)
            self.assertEqual(len(report["candidates"]), 1)
            self.assertIn(
                "offline-python-x64-installer",
                report["candidates"][0]["roles"],
            )
            self.assertFalse(report["authoritative"])
            self.assertFalse(report["ga_eligible"])
            self.assertFalse(report["ready_for_media_manifest"])

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
