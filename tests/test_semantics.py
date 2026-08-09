import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from psmatrix.models import ExecutionResult
from psmatrix.runner import ScriptRunner
from psmatrix.verifier import verify


class SemanticVerifierTests(unittest.TestCase):
    @staticmethod
    def execution() -> ExecutionResult:
        return ExecutionResult(
            command=["pwsh"], cwd="/tmp", exit_code=0, timed_out=False,
            duration_ms=1, stdout="ok\n", stderr="",
        )

    def test_stream_native_module_and_manifest_contracts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            observation = {
                "streams": {
                    "success": {"count": 1, "records": []},
                    "error": {"count": 0, "records": []},
                    "warning": {"count": 1, "records": [{"message": "warn"}]},
                    "verbose": {"count": 1, "records": [{"message": "details"}]},
                    "debug": {"count": 0, "records": []},
                    "information": {"count": 0, "records": []},
                },
                "native": {"observed": True, "last_exit_code": 0},
                "module": {
                    "module_name": "math-tools",
                    "version": "1.0.0",
                    "exported_commands": ["Add-Numbers"],
                },
                "manifest": {
                    "kind": "ModuleManifest", "valid": True,
                    "name": "math-tools", "version": "1.0.0",
                    "root_module": "math-tools.psm1",
                    "exported_functions": ["Add-Numbers"],
                    "exported_cmdlets": [], "exported_aliases": [],
                },
                "semantic": {
                    "cases": [{
                        "index": 1, "name": "Add-Numbers", "status": "completed",
                        "output_count": 1, "output_json": json.dumps({"items": [5]}),
                        "last_exit_code": None,
                    }]
                },
            }
            contract = {
                "schema": 1,
                "expect": {
                    "exit_code": 0,
                    "native_exit_code": 0,
                    "streams": {
                        "error": 0,
                        "warning": {"count": 1, "contains": ["warn"]},
                        "verbose": {"min_count": 1, "regex": ["detail"]},
                    },
                    "module": {
                        "name": "math-tools",
                        "version": "1.0.0",
                        "exported_commands": ["Add-Numbers"],
                        "commands": [{
                            "name": "Add-Numbers",
                            "expect": {"status": "completed", "output_count": 1, "output_equals": 5},
                        }],
                    },
                    "manifest": {
                        "kind": "ModuleManifest", "valid": True,
                        "name": "math-tools", "version": "1.0.0",
                        "root_module": "math-tools.psm1",
                        "exported_functions": ["Add-Numbers"],
                        "exported_cmdlets": [], "exported_aliases": [],
                    },
                },
            }
            checks = verify(root, self.execution(), contract, observation)
            self.assertTrue(all(check.passed for check in checks), [check for check in checks if not check.passed])

    def test_unexpected_stream_and_native_exit_policies(self):
        observation = {
            "streams": {"error": {"count": 1, "records": [{"message": "bad"}]}},
            "native": {"observed": True, "last_exit_code": 7},
        }
        contract = {"schema": 1, "expect": {"exit_code": 0}}
        self.assertIn("error stream", ScriptRunner._stream_failure(observation, contract, mode="auto"))
        self.assertIn("LASTEXITCODE=7", ScriptRunner._native_exit_failure(observation, contract, mode="auto"))
        contracted = {"schema": 1, "expect": {"streams": {"error": 1}, "native_exit_code": 7}}
        self.assertIsNone(ScriptRunner._stream_failure(observation, contracted, mode="auto"))
        self.assertIsNone(ScriptRunner._native_exit_failure(observation, contracted, mode="auto"))

    def test_coverage_policy(self):
        self.assertIsNone(ScriptRunner._coverage_failure(
            {"coverage": {"status": "completed", "percent": 90.0}},
            mode="required", fail_under=80.0,
        ))
        self.assertIn("below", ScriptRunner._coverage_failure(
            {"coverage": {"status": "completed", "percent": 50.0}},
            mode="auto", fail_under=80.0,
        ))
        self.assertIn("required", ScriptRunner._coverage_failure(
            {"coverage": {"status": "unavailable"}},
            mode="required", fail_under=None,
        ))

    def test_semantic_contract_contains_only_bounded_expectations_and_posix_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "internal" / "semantic-contract.json"
            uid = 65534 if hasattr(os, "geteuid") and os.geteuid() == 0 else None
            gid = 65534 if uid is not None else None
            contract = {
                "schema": 1,
                "expect": {
                    "module": {"name": "safe-module"},
                    "manifest": {"kind": "ModuleManifest"},
                },
                # These fields intentionally model sensitive/execution material
                # that must never be copied into the child semantic contract.
                "environment": {"SECRET": "must-not-leak"},
                "parameters": {"ApiKey": "must-not-leak"},
                "stdin": "must-not-leak",
            }
            ScriptRunner._write_semantic_contract(path, contract, uid=uid, gid=gid)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(set(payload), {"schema", "module", "manifest"})
            self.assertEqual(payload["schema"], 1)
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("must-not-leak", serialized)
            self.assertNotIn("environment", serialized)
            self.assertNotIn("parameters", serialized)
            self.assertNotIn("stdin", serialized)

            details = path.stat()
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(details.st_mode), 0o600)
                if uid is not None:
                    self.assertEqual(details.st_uid, uid)
                    self.assertEqual(details.st_gid, gid)

    def test_generated_semantic_tests_include_module_cases_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / "tool.psm1"
            module.write_text("function Get-Tool { 1 }; Export-ModuleMember Get-Tool", encoding="utf-8")
            contract = {
                "schema": 1,
                "expect": {"module": {
                    "exported_commands": ["Get-Tool"],
                    "commands": [{"name": "Get-Tool", "expect": {"output_equals": 1}}],
                }},
            }
            generated = ScriptRunner._write_generated_pester_smoke(root, module, contract)
            text = generated.read_text(encoding="utf-8")
            self.assertIn("exact contracted command set", text)
            self.assertIn("semantic command case", text)

            manifest = root / "tool.psd1"
            manifest.write_text("@{ RootModule='tool.psm1'; ModuleVersion='1.0.0' }", encoding="utf-8")
            generated_manifest = ScriptRunner._write_generated_pester_smoke(root, manifest, {
                "schema": 1, "expect": {"manifest": {"kind": "ModuleManifest"}}
            })
            self.assertIn("Test-ModuleManifest", generated_manifest.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
