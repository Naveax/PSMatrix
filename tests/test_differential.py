import unittest

from psmatrix.differential import compare_targets
from psmatrix.models import ExecutionResult, FileChange, TargetReport, VerificationCheck


def target(version: str, *, stdout: str = "same", shape: str = "System.String") -> TargetReport:
    return TargetReport(
        runtime_id=f"powershell-{version}-linux-x64",
        runtime_version=version,
        source="/work/test.ps1",
        source_sha256="a" * 64,
        status="PASS",
        parse_ok=True,
        execution=ExecutionResult(
            command=["pwsh"],
            cwd="/work",
            exit_code=0,
            timed_out=False,
            duration_ms=10,
            stdout=stdout,
            stderr="",
        ),
        verification=[VerificationCheck("exit_code", True, "process", 0, 0)],
        file_changes=[FileChange("result.json", "created", size_after=10, sha256_after="b" * 64)],
        observation={
            "output_count": 1,
            "output_truncated": False,
            "output_shapes": [{"index": 0, "base_type": shape, "pstype_names": [shape], "properties": []}],
            "error": None,
        },
        analysis={"ast": {"commands": [{"name": "Write-Output"}], "type_names": []}},
    )


class DifferentialTests(unittest.TestCase):
    def test_equivalent_targets(self):
        report = compare_targets([target("7.4.18"), target("7.6.4")])
        self.assertEqual(report[0]["status"], "EQUIVALENT")
        self.assertEqual(report[0]["issue_count"], 0)

    def test_detects_object_and_output_differences(self):
        report = compare_targets(
            [target("7.4.18"), target("7.6.4", stdout="changed", shape="System.Int32")]
        )
        dimensions = {item["dimension"] for item in report[0]["issues"]}
        self.assertIn("execution", dimensions)
        self.assertIn("observation", dimensions)


    def test_detects_dependency_and_hook_differences(self):
        baseline = target("7.4.18")
        candidate = target("7.6.4")
        baseline.dependencies = {
            "status": "satisfied",
            "checks": [{"kind": "native_command", "name": "git", "passed": True, "expected": "2", "actual": {"version": "2"}}],
        }
        candidate.dependencies = {
            "status": "satisfied",
            "checks": [{"kind": "native_command", "name": "git", "passed": True, "expected": "2", "actual": {"version": "3"}}],
        }
        baseline.hooks = {"setup": [{"execution": {"exit_code": 0, "timed_out": False, "resource_violation": None}, "payload": {"status": "completed"}}], "teardown": []}
        candidate.hooks = {"setup": [{"execution": {"exit_code": 1, "timed_out": False, "resource_violation": None}, "payload": {"status": "failed"}}], "teardown": []}
        report = compare_targets([baseline, candidate])
        dimensions = {item["dimension"] for item in report[0]["issues"]}
        self.assertIn("dependencies", dimensions)
        self.assertIn("hooks", dimensions)

    def test_unavailable_runtime_only_contributes_status_difference(self):
        missing = TargetReport(
            runtime_id="powershell-7.4.18-linux-x64",
            runtime_version="7.4.18",
            source="/work/test.ps1",
            source_sha256="a" * 64,
            status="UNTESTED_RUNTIME",
            parse_ok=False,
        )
        report = compare_targets([missing, target("7.6.4")])
        self.assertEqual(report[0]["baseline_runtime"], "powershell-7.6.4-linux-x64")
        self.assertEqual([item["dimension"] for item in report[0]["issues"]], ["status"])
