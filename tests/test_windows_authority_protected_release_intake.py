import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntake.ps1"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityProtectedReleaseIntakeTests(unittest.TestCase):
    def test_intake_is_isolated_fail_closed_and_stops_at_release_closure(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")

        required = (
            "import_windows_authority_protected_release.py",
            "IMPORTED_VERIFIED",
            "release_manifest_verified",
            "release_signature_verified",
            "reviewed_artifact_lock_verified",
            "Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "-SearchRoot @($reportedDestination)",
            "Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "Test-PSMatrixWindowsAuthorityReleaseManifestClosure.ps1",
            "release_authority_status -ne 'READY'",
            "closure.status -ne 'READY'",
            "ready_for_release_artifact_recovery -ne $true",
            "Canonical signed release manifest was selected outside the isolated imported RC release root.",
            "status = 'RELEASE_CLOSURE_READY'",
            "broad_downloads_search_used = $false",
            "media_manifest_materialized = $false",
            "operation_package_rebuilt = $false",
            "authoritative = $false",
            "ga_eligible = $false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "$HOME\\Downloads",
            "$env:USERPROFILE\\Downloads",
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "Invoke-PSMatrixAuthoritativeWindowsGA.ps1",
            "New-VM",
            "Checkpoint-VM",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

        importer = text.index("import_windows_authority_protected_release.py")
        inventory = text.index("Get-PSMatrixWindowsAuthorityMediaInventory.ps1")
        canonical = text.index("Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1")
        closure = text.index("Test-PSMatrixWindowsAuthorityReleaseManifestClosure.ps1")
        final_status = text.index("status = 'RELEASE_CLOSURE_READY'")
        self.assertLess(importer, inventory)
        self.assertLess(inventory, canonical)
        self.assertLess(canonical, closure)
        self.assertLess(closure, final_status)

    def test_source_preflight_tracks_protected_release_intake(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "scripts/ga/Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntake.ps1",
            "tests/test_windows_authority_protected_release_intake.py",
            "tests.test_windows_authority_protected_release_intake",
            "protected_release_intake_contract",
            "protected_release_intake_powershell_parse",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
