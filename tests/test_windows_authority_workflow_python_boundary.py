from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authoritative.yml"
PACK03 = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityWorkflowPythonBoundaryTests(unittest.TestCase):
    def test_workflow_binds_controller_python_to_setup_output_and_redacts_native_failures(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "id: setup_controller_python",
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0",
            "CONTROLLER_PYTHON: ${{ steps.setup_controller_python.outputs.python-path }}",
            "function Resolve-TrustedControllerPython([string]$Candidate)",
            "[System.IO.Path]::IsPathFullyQualified($Candidate)",
            "$full = [System.IO.Path]::GetFullPath($Candidate)",
            "Assert-NoExistingLinkOrReparseComponents $parent 'Trusted workflow controller python parent'",
            "Trusted workflow controller python output must be an absolute path.",
            "Trusted workflow controller python executable must not be a link or reparse point.",
            "Trusted workflow controller python executable name mismatch.",
            "Trusted workflow controller python must stay outside the repository.",
            "$controllerPython = Resolve-TrustedControllerPython $env:CONTROLLER_PYTHON",
            "$bootstrapOutput = (& $controllerPython -m psmatrix",
            "$pipOutput = (& $controllerPython -m pip install",
            "$packageOrigin = (& $controllerPython -c",
            "$installedVersion = (& $controllerPython -c",
            "Checkout bootstrap release verification failed with exit code $bootstrapExit; command output was intentionally redacted.",
            "Offline exact release wheel installation failed with exit code $pipExit; command output was intentionally redacted.",
            "Failed to resolve installed PSMatrix package origin; command output was intentionally redacted.",
            "Failed to resolve installed PSMatrix distribution version; command output was intentionally redacted.",
        )
        for value in required:
            with self.subTest(required=value):
                self.assertIn(value, text)

        self.assertIsNone(
            re.search(
                r"(?im)^\s*(?:&\s+)?['\"]?python(?:\.exe)?['\"]?(?:\s|$)",
                text,
            ),
            "authoritative workflow must not invoke ambient python directly",
        )
        self.assertNotIn("Get-Command python", text)
        self.assertNotIn("Test-ExactProcessPathParent", text)
        self.assertNotIn("$commands[0].Path", text)
        self.assertNotIn("# v6.2.0", text)
        self.assertNotIn("$command.Source", text)
        self.assertNotIn("`n$packageOrigin", text)
        self.assertNotIn("`n$installedVersion", text)
        self.assertGreaterEqual(text.count("command output was intentionally redacted."), 4)

    def test_pack03_preflight_executes_and_parses_boundary_sources(self) -> None:
        text = PACK03.read_text(encoding="utf-8")
        for required in (
            'tests/test_windows_authority_workflow_python_boundary.py',
            'tests.test_windows_authority_workflow_python_boundary',
            "'scripts/ga/Invoke-PSMatrixAuthoritativeWindowsGA.ps1'",
            "'authoritative_operator_powershell_parse': 'PASS'",
            "'authoritative_workflow_python_boundary_contract': 'PASS'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)

    def test_workflow_keeps_exact_release_and_ga_semantics(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "ref: ${{ inputs.release_commit }}",
            "if ($iterations -lt 10 -or $iterations -gt 100)",
            "^psmatrix-2\\.0\\.0(?:rc[0-9]+)?-release\\.json$",
            "--no-index",
            "--no-deps",
            "Invoke-PSMatrixAuthoritativeWindowsGA.ps1",
            "Upload authoritative Windows evidence",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertNotIn("continue-on-error: true", text)


if __name__ == "__main__":
    unittest.main()
