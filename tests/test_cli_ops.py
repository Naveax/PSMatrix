import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from psmatrix.cli import main
from psmatrix.http_sessions import ProjectSessionStore, SessionLimits


class CliOperationsTests(unittest.TestCase):
    def test_snapshot_metrics_audit_reports_and_support_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            store = ProjectSessionStore(home, limits=SessionLimits(ttl_seconds=600))
            record = store.create("cli-user")
            store.upload_text(record, "tool.ps1", "Write-Output 'ok'\n")
            report = record.root / ".psmatrix" / "mcp" / "report.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps({"kind": "psmatrix.compatibility-report", "status": "PASS"}), encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", str(home), "ops", "snapshot"])
            self.assertEqual(code, 0)
            snapshot = json.loads(output.getvalue())
            self.assertEqual(snapshot["kind"], "psmatrix.operations-snapshot")

            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", str(home), "ops", "metrics"])
            self.assertEqual(code, 0)
            self.assertIn("psmatrix_info", output.getvalue())

            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", str(home), "ops", "audit", "--limit", "10"])
            self.assertEqual(code, 0)
            self.assertGreaterEqual(json.loads(output.getvalue())["count"], 1)

            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", str(home), "ops", "reports", "--root", str(record.root), "--limit", "10"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["items"][0]["status"], "PASS")

            bundle = root / "support.zip"
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", str(home), "ops", "support-bundle", "--output", str(bundle)])
            self.assertEqual(code, 0)
            self.assertTrue(bundle.is_file())
            with zipfile.ZipFile(bundle) as archive:
                self.assertIn("manifest.json", archive.namelist())

    def test_certificate_warning_horizon_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", temp, "ops", "certificates", "--warning-days", "30"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["critical"], 0)


if __name__ == "__main__": unittest.main()
