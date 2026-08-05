import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.full_matrix import (
    FullMatrixError,
    FullMatrixSpec,
    execute_full_matrix,
    plan_full_matrix,
    write_full_matrix_template,
)


def target(runtime_id: str, version: str, source: str, *, output: str = "ok"):
    return {
        "runtime_id": runtime_id,
        "runtime_version": version,
        "source": source,
        "source_sha256": "a" * 64,
        "status": "PASS",
        "parse_ok": True,
        "parse_diagnostics": [],
        "execution": {
            "command": ["pwsh"], "cwd": ".", "exit_code": 0, "timed_out": False,
            "duration_ms": 1, "stdout": output, "stderr": "",
            "stdout_truncated": False, "stderr_truncated": False, "resource_violation": None,
        },
        "test_execution": None,
        "tests": {}, "verification": [], "file_changes": [], "windows_requirements": [],
        "warnings": [], "sandbox": {}, "analysis": {}, "observation": {}, "runtime": {},
        "inputs": {}, "dependencies": {}, "hooks": {}, "cache": {},
    }


class FullMatrixTests(unittest.TestCase):
    def test_json_schema_accepts_exact_windows_core_runtime_ids(self):
        import re
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "full-matrix.schema.json").read_text(encoding="utf-8"))
        pattern = schema["properties"]["targets"]["items"]["oneOf"][1]["properties"]["runtime_id"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "windows-powershell-5.1"))
        self.assertIsNotNone(re.fullmatch(pattern, "powershell-7.6.4-windows-x64"))
        self.assertIsNotNone(re.fullmatch(pattern, "powershell-7.7.0-preview.2-windows-arm64"))
        self.assertIsNone(re.fullmatch(pattern, "powershell-7.6-windows-x64"))
        self.assertIsNone(re.fullmatch(pattern, "windows-powershell-6.0"))

    def test_template_declares_linux_and_windows_core_plus_desktop_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "full.json"
            result = write_full_matrix_template(output)
            spec = FullMatrixSpec.load(output)
            self.assertEqual(result["targets"], 25)
            self.assertTrue(Path(result["allowance_path"]).is_file())
            self.assertEqual(len(spec.targets), 25)
            self.assertIsNotNone(spec.allowance_manifest)
            self.assertEqual(sum(t.kind == "remote" for t in spec.targets), 13)
            self.assertEqual(spec.baseline_runtime, "powershell-7.6.4-linux-x64")


    def test_expired_difference_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "differences.json").write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.differential-allowances", "name": "expired",
                "expires_at": "2020-01-01T00:00:00+00:00",
                "rules": [{"dimension": "execution", "reason": "temporary"}],
            }), encoding="utf-8")
            spec = root / "full.json"
            spec.write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [{"id": "linux", "kind": "local", "version": "7.6.4"}],
                "differential": {"allowance_file": "differences.json"},
            }), encoding="utf-8")
            with self.assertRaises(FullMatrixError):
                FullMatrixSpec.load(spec)

    def test_unsafe_endpoint_and_duplicate_runtime_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = {
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [
                    {"id": "a", "kind": "remote", "runtime_id": "windows-powershell-5.1", "endpoint": "../escape.json"}
                ],
            }
            path = root / "full.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(FullMatrixError):
                FullMatrixSpec.load(path)

            payload["targets"] = [
                {"id": "a", "kind": "local", "version": "7.6.4"},
                {"id": "b", "kind": "local", "version": "7.6.4"},
            ]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(FullMatrixError):
                FullMatrixSpec.load(path)

    def test_plan_is_incomplete_when_required_endpoints_and_runtimes_are_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec_path = root / "full.json"
            spec_path.write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [
                    {"id": "linux", "kind": "local", "version": "7.6.4"},
                    {"id": "win", "kind": "remote", "runtime_id": "windows-powershell-5.1", "endpoint": "endpoints/win.json"},
                ],
            }), encoding="utf-8")
            result = plan_full_matrix(home=root / "home", spec_path=spec_path)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(set(result["coverage"]["missing_required"]), {"linux", "win"})

    def test_local_and_authoritative_remote_targets_are_combined_with_differences(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            endpoint_path = root / "endpoint.json"
            endpoint_path.write_text("{}", encoding="utf-8")
            spec_path = root / "full.json"
            spec_path.write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [
                    {"id": "linux", "kind": "local", "version": "7.6.4"},
                    {"id": "win", "kind": "remote", "runtime_id": "windows-powershell-5.1", "endpoint": "endpoint.json"},
                ],
                "differential": {"mode": "report", "baseline_runtime": "powershell-7.6.4-linux-x64"},
            }), encoding="utf-8")

            def fake_run(command, **kwargs):
                report_path = Path(command[command.index("--report-json") + 1])
                report_path.write_text(json.dumps({
                    "status": "PASS", "targets": [target("powershell-7.6.4-linux-x64", "7.6.4", str(source), output="linux")]
                }), encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            endpoint = SimpleNamespace(worker_id="worker-51", expected_runtime_id="windows-powershell-5.1")
            remote = {
                "report": {"status": "PASS", "targets": [target("windows-powershell-5.1", "5.1", "C:/tool.ps1", output="windows")]},
                "capabilities": {"authoritative": True, "runtime_id": "windows-powershell-5.1"},
                "reset": {"required": True, "before": {"passed": True}, "after": {"passed": True}},
                "transfer": {"mode": "inline"},
            }
            with patch("psmatrix.full_matrix.subprocess.run", side_effect=fake_run), \
                 patch("psmatrix.full_matrix.RemoteEndpoint.load", return_value=endpoint), \
                 patch("psmatrix.full_matrix.submit_remote_job", return_value=remote):
                report = execute_full_matrix(
                    home=root / "home", root=root, entrypoint=source, spec_path=spec_path,
                    include=[], local_args=[], remote_options={}, timeout=30, jobs=2,
                )
            self.assertEqual(report.status, "PASS_WITH_DIFFERENCES")
            self.assertEqual(report.matrix["coverage"]["passed"], 2)
            self.assertGreater(report.matrix["unallowed_differences"], 0)
            self.assertEqual({t.runtime["platform"] for t in report.targets}, {"linux", "windows"})

    def test_allowance_can_make_strict_cross_os_difference_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            (root / "endpoint.json").write_text("{}", encoding="utf-8")
            spec_path = root / "full.json"
            spec_path.write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [
                    {"id": "linux", "kind": "local", "version": "7.6.4"},
                    {"id": "win", "kind": "remote", "runtime_id": "windows-powershell-5.1", "endpoint": "endpoint.json"},
                ],
                "differential": {
                    "mode": "strict", "baseline_runtime": "powershell-7.6.4-linux-x64",
                    "allow": [
                        {"dimension": "execution", "candidate_runtime": "windows-powershell-5.1", "reason": "platform text"}
                    ],
                },
            }), encoding="utf-8")

            def fake_run(command, **kwargs):
                report_path = Path(command[command.index("--report-json") + 1])
                report_path.write_text(json.dumps({"targets": [target("powershell-7.6.4-linux-x64", "7.6.4", str(source), output="linux")]}), encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            endpoint = SimpleNamespace(worker_id="worker-51", expected_runtime_id="windows-powershell-5.1")
            remote = {
                "report": {"targets": [target("windows-powershell-5.1", "5.1", "C:/tool.ps1", output="windows")]},
                "capabilities": {"authoritative": True, "runtime_id": "windows-powershell-5.1"},
                "reset": {"required": True, "before": {"passed": True}, "after": {"passed": True}},
            }
            with patch("psmatrix.full_matrix.subprocess.run", side_effect=fake_run), \
                 patch("psmatrix.full_matrix.RemoteEndpoint.load", return_value=endpoint), \
                 patch("psmatrix.full_matrix.submit_remote_job", return_value=remote):
                report = execute_full_matrix(
                    home=root / "home", root=root, entrypoint=source, spec_path=spec_path,
                    include=[], local_args=[], remote_options={}, timeout=30, jobs=1,
                )
            self.assertEqual(report.status, "PASS")
            self.assertEqual(report.matrix["unallowed_differences"], 0)
            issue = report.differential[0]["issues"][0]
            self.assertTrue(issue["allowed"])

    def test_missing_required_remote_is_incomplete_not_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            spec_path = root / "full.json"
            spec_path.write_text(json.dumps({
                "schema": 1, "kind": "psmatrix.full-matrix-spec", "name": "full",
                "targets": [
                    {"id": "win", "kind": "remote", "runtime_id": "windows-powershell-4.0", "endpoint": "missing.json"}
                ],
            }), encoding="utf-8")
            report = execute_full_matrix(
                home=root / "home", root=root, entrypoint=source, spec_path=spec_path,
                include=[], local_args=[], remote_options={}, timeout=30,
            )
            self.assertEqual(report.status, "INCOMPLETE")
            self.assertEqual(report.targets[0].status, "UNTESTED_RUNTIME")


if __name__ == "__main__":
    unittest.main()
