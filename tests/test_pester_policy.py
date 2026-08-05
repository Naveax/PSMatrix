import tempfile
import unittest
from pathlib import Path

from psmatrix.runner import ScriptRunner


class PesterPolicyTests(unittest.TestCase):
    def test_discovers_conventional_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            test = root / "tool.Tests.ps1"
            source.write_text("'ok'", encoding="utf-8")
            test.write_text("Describe 'tool' {}", encoding="utf-8")
            self.assertEqual(ScriptRunner._discover_pester_tests(source), [Path("tool.Tests.ps1")])

    def test_generated_module_smoke_imports_without_reexecuting_script_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module_source = root / "tool.psm1"
            module_source.write_text("function Get-Tool {}", encoding="utf-8")
            generated = ScriptRunner._write_generated_pester_smoke(root, module_source)
            text = generated.read_text(encoding="utf-8")
            self.assertIn("Parser]::ParseFile", text)
            self.assertIn("Import-Module", text)

            script_source = root / "danger.ps1"
            script_source.write_text("throw 'do not execute twice'", encoding="utf-8")
            generated_script = ScriptRunner._write_generated_pester_smoke(root, script_source)
            script_text = generated_script.read_text(encoding="utf-8")
            self.assertIn("Parser]::ParseFile", script_text)
            self.assertNotIn("& $env:PSMATRIX_SOURCE", script_text)

    def test_required_mode_fails_without_tests_or_module(self):
        self.assertIn(
            "no matching",
            ScriptRunner._pester_failure({"status": "no-tests"}, mode="required"),
        )
        self.assertIn(
            "healthy installation",
            ScriptRunner._pester_failure({"status": "unavailable"}, mode="required"),
        )

    def test_completed_failure_is_rejected(self):
        self.assertIn(
            "2 failed",
            ScriptRunner._pester_failure(
                {"status": "completed", "failed": 2}, mode="auto"
            ),
        )
        self.assertIsNone(
            ScriptRunner._pester_failure(
                {"status": "completed", "failed": 0}, mode="required"
            )
        )


if __name__ == "__main__":
    unittest.main()
