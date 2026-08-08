import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "ga" / "Initialize-PSMatrixWindowsAuthorityLab.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "controller-bootstrap-contract.json"
INFRA_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-infrastructure-preflight.yml"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityControllerBootstrapTests(unittest.TestCase):
    def test_contract_freezes_controller_and_authority_boundaries(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-controller-bootstrap-contract")
        self.assertFalse(value["authority"]["bootstrap_is_authoritative_evidence"])
        self.assertFalse(value["authority"]["bootstrap_is_ga_eligible"])
        self.assertEqual(
            value["controller"]["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        self.assertEqual(
            value["controller"]["required_hyper_v_commands"],
            ["Get-VM", "Get-VMHost", "Get-VMSnapshot", "Restore-VMSnapshot", "Checkpoint-VM"],
        )
        self.assertEqual(
            value["layout"]["required_directories"],
            ["media/release", "media/external", "operation", "config", "trust-home"],
        )
        self.assertEqual(value["layout"]["isolated_release_root"], "media/release/2.0.0rc3")
        self.assertEqual(value["layout"]["isolated_operation_root"], "operation/2.0.0rc3")
        self.assertEqual(
            value["controller"]["release_public_key_source"],
            "verified-protected-release-bundle",
        )
        self.assertFalse(value["controller"]["release_public_key_secret_required"])
        self.assertEqual(
            value["required_runtime_ids"],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        )
        self.assertEqual(
            value["infrastructure_dispatch_inputs"]["protected_release_intake_status"],
            "RELEASE_CLOSURE_READY",
        )
        self.assertEqual(
            value["infrastructure_dispatch_inputs"]["operation_package_status"],
            "READY_FOR_WINDOWS_HOST",
        )
        self.assertEqual(
            value["infrastructure_dispatch_inputs"]["operation_package_binding_status"],
            "PASS",
        )
        self.assertFalse(value["completion"]["ga_eligible"])

    def test_bootstrap_is_fail_closed_and_never_creates_fake_evidence(self) -> None:
        text = BOOTSTRAP.read_text(encoding="utf-8")
        required = (
            "[switch]$CreateLayout",
            "[switch]$RequireRunnerService",
            "[switch]$RequireReleaseInputs",
            "Test-IsAdministrator",
            "Win32_ComputerSystem",
            "VirtualizationFirmwareEnabled",
            "Microsoft-Hyper-V-All",
            "Import-Module Hyper-V",
            "Get-Service -Name vmms",
            "Get-VMSnapshot",
            "Restore-VMSnapshot",
            "Checkpoint-VM",
            "actions.runner.*PSMatrix*",
            "media\\release\\2.0.0rc3",
            "media\\external",
            "operation\\2.0.0rc3",
            "RELEASE_CLOSURE_READY",
            "windows-lab-media.json",
            "READY_FOR_WINDOWS_HOST",
            "ready_for_release_artifact_recovery",
            "ready_to_dispatch_infrastructure_preflight",
            "release_public_key_source = 'verified-protected-release-bundle'",
            "release_public_key_secret_required = $false",
            "authority_level = 'local-controller-bootstrap'",
            "authoritative = $false",
            "ga_eligible = $false",
            "Bootstrap readiness is not infrastructure evidence",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertIn("-endpoint.example.json", text)
        self.assertIn("-image.example.json", text)
        self.assertIn("templates_must_not_use_validator_filenames", CONTRACT.read_text(encoding="utf-8"))
        self.assertNotIn("protected secret: PSMATRIX_RELEASE_PUBLIC_KEY", text)
        self.assertNotIn("Join-Path $root 'release'", text)
        self.assertNotIn("Invoke-Expression", text)

    def test_infrastructure_workflow_initializes_evidence_before_checkouts(self) -> None:
        text = INFRA_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "Initialize fail-closed infrastructure evidence and exact paths",
            "PSMATRIX_WINDOWS_INFRA_EVIDENCE",
            "release_commit must contain exactly 40 lowercase hexadecimal characters",
            "Check out current infrastructure controls",
            "Check out exact RC3 release source",
            "path: control",
            "path: release-source",
            "Install exact signed RC3 controller package offline",
            "Revalidate exact operation package binding",
            "controller-context.json",
            "Record fail-closed infrastructure state",
            "preflight-failure.json",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertLess(
            text.index("Initialize fail-closed infrastructure evidence and exact paths"),
            text.index("Check out current infrastructure controls"),
        )
        self.assertNotIn("continue-on-error: true", text)
        self.assertNotIn("PSMATRIX_RELEASE_PUBLIC_KEY: ${{ secrets.PSMATRIX_RELEASE_PUBLIC_KEY }}", text)

    def test_source_preflight_tracks_bootstrap_contract(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "ga-packs/03-authoritative-windows/**",
            "scripts/ga/Initialize-PSMatrixWindowsAuthorityLab.ps1",
            "tests/test_windows_authority_controller_bootstrap.py",
            "Parse Windows authority PowerShell scripts",
            "tests.test_windows_authority_controller_bootstrap",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
