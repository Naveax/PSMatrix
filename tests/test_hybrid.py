import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.hybrid import HybridError, execute_hybrid_matrix


class HybridTests(unittest.TestCase):
    def test_local_and_remote_reports_are_combined_only_after_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            endpoint_path = root / "endpoint.json"
            endpoint_path.write_text("{}", encoding="utf-8")

            def fake_run(command, **kwargs):
                report_path = Path(command[command.index("--report-json") + 1])
                report_path.write_text(json.dumps({
                    "status": "PASS",
                    "targets": [{"runtime_id": "powershell-7.6.4-linux-x64", "status": "PASS"}],
                    "diagnostics": [],
                }), encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="local", stderr="")

            endpoint = SimpleNamespace(worker_id="worker-5.1")
            verified = {
                "report": {"status": "PASS", "targets": [{"runtime_id": "windows-powershell-5.1", "status": "PASS"}], "diagnostics": []},
                "capabilities": {"runtime_id": "windows-powershell-5.1", "authoritative": True},
                "reset": {"required": True, "before": {"passed": True}, "after": {"passed": True}},
            }
            with patch("psmatrix.hybrid.subprocess.run", side_effect=fake_run), \
                 patch("psmatrix.hybrid.RemoteEndpoint.load", return_value=endpoint), \
                 patch("psmatrix.hybrid.submit_remote_job", return_value=verified):
                report = execute_hybrid_matrix(
                    home=root / "home", root=root, entrypoint=source,
                    local_runtimes=["7.6.4"], local_args=[], endpoint_paths=[endpoint_path],
                    include=[], remote_options={}, timeout=30,
                )
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(len(report["targets"]), 2)
            self.assertTrue(report["matrix"]["remote_workers"][0]["signature_valid"])

    def test_managed_local_arguments_and_empty_matrix_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            with self.assertRaises(HybridError):
                execute_hybrid_matrix(
                    home=root / "home", root=root, entrypoint=source,
                    local_runtimes=[], local_args=[], endpoint_paths=[], include=[], remote_options={}, timeout=30,
                )
            with self.assertRaises(HybridError):
                execute_hybrid_matrix(
                    home=root / "home", root=root, entrypoint=source,
                    local_runtimes=["7.6.4"], local_args=["--report-json"], endpoint_paths=[], include=[], remote_options={}, timeout=30,
                )


if __name__ == "__main__":
    unittest.main()
