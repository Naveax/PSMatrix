import tempfile
import unittest
from pathlib import Path

from psmatrix.static_analysis import analyze_source


class StaticAnalysisTests(unittest.TestCase):
    def test_detects_windows_and_risk_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.ps1"
            path.write_text(
                "Set-ItemProperty HKLM:\\Software\\X -Name Y -Value 1\nInvoke-Expression $x",
                encoding="utf-8",
            )
            result = analyze_source(path)
            self.assertIn("registry", result["windows_requirements"])
            self.assertIn("dynamic-execution", result["risks"])
    def test_ast_analysis_resolves_dynamic_execution_and_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.ps1"
            path.write_text("$cmd = 'Get-ChildItem'; & $cmd", encoding="utf-8")
            ast = {
                "commands": [
                    {
                        "name": "",
                        "invocation_operator": "Ampersand",
                        "parameters": [],
                        "elements": ["$cmd"],
                        "text": "& $cmd",
                        "line": 1,
                        "column": 25,
                    },
                    {
                        "name": "Import-Module",
                        "invocation_operator": "Unknown",
                        "parameters": ["Name"],
                        "elements": ["Import-Module", "-Name", "Pester"],
                        "text": "Import-Module -Name Pester",
                        "line": 2,
                        "column": 1,
                    },
                ],
                "type_names": ["System.Reflection.Assembly"],
                "provider_paths": [],
                "using_statements": [],
                "requires": [],
            }
            result = analyze_source(path, ast)
            self.assertEqual(result["analysis_mode"], "target-runtime-ast")
            self.assertIn("dynamic-execution", result["risks"])
            self.assertIn("reflection", result["risks"])
            self.assertIn("Pester", result["dependencies"]["modules"])
            self.assertTrue(any(item["code"] == "PSM1001" for item in result["findings"]))
