from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authoritative.yml"
PACK03 = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityWorkflowPythonBoundaryTests(unittest.TestCase):
    def test_workflow_pins_controller_python_and_redacts_native_failures(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "function Resolve-TrustedControllerPython()",
            "Get-Command python -CommandType Application -All",
            "$commandPath = [string]$commands[0].Path",
            "Test-ExactProcessPathParent",
            "Assert-NoExistingLinkOrReparseComponents $parent 'Trusted workflow controller python parent'",
            "Trusted workflow controller python parent must be an exact process PATH entry.",
            "Trusted workflow controller python must not expose a filesystem link target.",
            "Trusted workflow controller python must stay outside the repository.",
            "$controllerPython = Resolve-TrustedControllerPython",
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
            re.search(r"(?m)^\s*&\s+python(?:\.exe)?\b", text),
            "authoritative workflow must not invoke ambient python directly",
        )
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
            with self.subTest(required=value):
                self.assertIn(required, text)
        self.assertNotIn("continue-on-error: true", text)


if __name__ == "__main__":
    unittest.main()
