import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-media-readiness-selfhosted.yml"
PLANNER = ROOT / "scripts" / "ga" / "New-PSMatrixWindowsAuthorityMediaManifest.ps1"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


class WindowsAuthorityRC4MediaReadinessTests(unittest.TestCase):
    def test_workflow_requires_exact_rc4_intake_and_active_authority(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-rc4-media-readiness-selfhosted",
            "environment: production-ga-windows-lab",
            "control_head must equal the exact workflow control head",
            "ga-packs\\03-authoritative-windows\\rc4-release-lock.json",
            "release-assets\\2.0.0rc4\\psmatrix-2.0.0rc4-release-public.pem",
            "Current RC4 public authority differs from release lock",
            "windows-authority-protected-release-intake.json",
            "schema -ne 2",
            "RELEASE_CLOSURE_READY",
            "release_authority_rotation_reviewed",
            "lost_previous_private_authority",
            "release_authority_rotated_during_signing",
            "Protected RC4 intake unexpectedly materialized media state",
            "Protected RC4 intake unexpectedly rebuilt operation state",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_workflow_enforces_exactly_two_isolated_search_roots(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "media\\release\\2.0.0rc4",
            "media\\external",
            "Expected exactly two distinct isolated media search roots",
            "isolated_rc4_media_search_roots=PASS count=2",
            "SearchRoot = $resolvedSearchRoots",
            "Get-PSMatrixWindowsAuthorityMediaInventory.ps1",
            "Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "Join-Path $HOME 'Downloads'",
            "Join-Path $HOME 'Desktop'",
            "$env:USERPROFILE\\Downloads",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_selection_materialization_stops_before_provisioning_and_hyper_v(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "config\\windows-authority-media-selection.json",
            "psmatrix.windows-authority-media-selection-materialization",
            "release_version -ne '2.0.0rc4'",
            "ready_for_provisioning_manifest_materialization",
            "provisioning_manifest_materialized -ne $false",
            "ready_for_hyper_v_provisioning -ne $false",
            "READY_FOR_PROVISIONING_MANIFEST_MATERIALIZATION",
            "READY_FOR_OPERATOR_SELECTION",
            "EXTERNAL_MEDIA_INCOMPLETE",
            "windows-authority-rc4-media-readiness",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1",
            "build_windows_authority_provisioning_manifest.py",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "authoritative = $true",
            "ga_eligible = $true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_common_planner_remains_release_version_generic(self) -> None:
        text = PLANNER.read_text(encoding="utf-8")
        self.assertIn("^2\\.0\\.0(?:rc[0-9]+)?$", text)
        self.assertIn("$releaseVersion = [string]$selectedManifest.manifest.version", text)
        self.assertIn("release_version = $releaseVersion", text)
        self.assertNotIn("release_version = '2.0.0rc3'", text)
        self.assertNotIn("release_version = '2.0.0rc4'", text)

    def test_source_preflight_tracks_rc4_media_readiness(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            ".github/workflows/ga-windows-authority-rc4-media-readiness-selfhosted.yml",
            "tests/test_windows_authority_rc4_media_readiness.py",
            "tests.test_windows_authority_rc4_media_readiness",
            "rc4_media_readiness_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
