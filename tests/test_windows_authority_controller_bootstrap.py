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
            value["required_runtime_ids"],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
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
            "ready_to_dispatch_infrastructure_preflight",
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
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", text)
        self.assertNotIn("Invoke-Expression", text)

    def test_infrastructure_workflow_initializes_evidence_before_checkout(self) -> None:
        text = INFRA_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "Initialize fail-closed infrastructure evidence",
            "PSMATRIX_WINDOWS_INFRA_EVIDENCE",
            "controller-context.json",
            "release_commit must contain exactly 40 lowercase hexadecimal characters",
            "Validate exact controller and protected environment",
            "Windows authority infrastructure checkout is not clean",
            "Record fail-closed infrastructure state",
            "preflight-failure.json",
            "Remove release public key materialization",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertLess(
            text.index("Initialize fail-closed infrastructure evidence"),
            text.index("Check out exact revision"),
        )
        self.assertLess(
            text.index("Remove release public key materialization"),
            text.index("Upload infrastructure preflight evidence"),
        )
        self.assertNotIn("continue-on-error: true", text)

    def test_source_preflight_tracks_bootstrap_contract(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "ga-packs/03-authoritative-windows/**",
            "scripts/ga/Initialize-PSMatrixWindowsAuthorityLab.ps1",
            "tests/test_windows_authority_controller_bootstrap.py",
            "Parse Windows controller bootstrap script",
            "tests.test_windows_authority_controller_bootstrap",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
