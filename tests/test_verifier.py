import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.models import ExecutionResult
from psmatrix.verifier import verify


class VerifierTests(unittest.TestCase):
    def execution(self, exit_code=0, stdout="done", stderr=""):
        return ExecutionResult(
            command=["pwsh"],
            cwd="/tmp",
            exit_code=exit_code,
            timed_out=False,
            duration_ms=1,
            stdout=stdout,
            stderr=stderr,
        )

    def test_independent_file_and_json_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "out.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
            contract = {
                "schema": 1,
                "expect": {
                    "exit_code": 0,
                    "stdout_contains": ["done"],
                    "files": [{"path": "out.json", "exists": True, "valid_json": True}],
                    "json": [{"path": "out.json", "property": "status", "equals": "ok"}],
                },
            }
            checks = verify(root, self.execution(), contract)
            self.assertTrue(all(check.passed for check in checks))

    def test_textual_success_does_not_override_failed_postcondition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            contract = {
                "schema": 1,
                "expect": {
                    "exit_code": 0,
                    "stdout_contains": ["success"],
                    "files": [{"path": "required.txt", "exists": True}],
                },
            }
            checks = verify(root, self.execution(stdout="success"), contract)
            self.assertTrue(any(not check.passed for check in checks))

    def test_verification_path_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            contract = {
                "schema": 1,
                "expect": {"files": [{"path": "../escape.txt", "exists": True}]},
            }
            with self.assertRaises(Exception):
                verify(root, self.execution(), contract)
