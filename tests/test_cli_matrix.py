import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from psmatrix.cli import main


class CliMatrixTests(unittest.TestCase):
    def test_plan_reports_missing_targets_without_claiming_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--home", temp, "plan", "--matrix", "core-6"])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(len(payload["targets"]), 3)
            self.assertTrue(
                all(item["status"] != "READY" for item in payload["targets"]),
                payload,
            )
            self.assertTrue(
                all(item["selected_backend"] == "oci" for item in payload["targets"]),
                payload,
            )

    def test_test_command_returns_incomplete_for_missing_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'ok'", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main([
                    "--home",
                    str(root / "home"),
                    "test",
                    str(source),
                    "--runtime",
                    "6.0.5",
                    "--psscriptanalyzer",
                    "off",
                    "--pester",
                    "off",
                    "--json",
                ])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(payload["schema"], 6)
            self.assertEqual(payload["status"], "INCOMPLETE")
            self.assertEqual(payload["targets"][0]["status"], "UNTESTED_RUNTIME")


class CliDifferentialEndToEndTests(unittest.TestCase):
    @staticmethod
    def _archive(root: Path, version: str, output: str, shape: str):
        import hashlib
        import io
        import tarfile

        script = f'''#!/usr/bin/env python3
import json
import sys
from pathlib import Path
args = sys.argv[1:]
if "-Command" in args:
    print({version!r})
    raise SystemExit(0)
harness = Path(args[args.index("-File") + 1]).name
if harness == "parse.ps1":
    print(json.dumps({{"schema": 2, "ok": True, "errors": [], "analysis": {{"commands": []}}, "analyzer": {{"status": "skipped"}}}}))
    raise SystemExit(0)
if harness == "execute.ps1":
    observation = Path(args[args.index("-ObservationPath") + 1])
    observation.parent.mkdir(parents=True, exist_ok=True)
    observation.write_text(json.dumps({{
        "schema": 1,
        "runtime": {{"version": {version!r}, "edition": "Core"}},
        "output_count": 1,
        "output_truncated": False,
        "output_shapes": [{{"index": 0, "base_type": {shape!r}, "pstype_names": [{shape!r}], "properties": []}}],
        "error": None,
    }}), encoding="utf-8")
    print({output!r})
    raise SystemExit(0)
print(json.dumps({{"status": "no-tests", "failed": 0}}))
raise SystemExit(0)
'''.encode()
        archive = root / f"powershell-{version}-linux-x64.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            info = tarfile.TarInfo("pwsh")
            info.mode = 0o755
            info.size = len(script)
            handle.addfile(info, io.BytesIO(script))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    @unittest.skipUnless(os.name == "posix", "Linux-native runtime archive fixture")
    def test_report_and_strict_differential_statuses(self):
        from psmatrix.models import RuntimeSpec
        from psmatrix.runtime import RuntimeManager

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            manager = RuntimeManager(home)
            for version, output, shape in (
                ("7.4.18", "old", "System.String"),
                ("7.6.4", "new", "System.Int32"),
            ):
                archive, digest = self._archive(root, version, output, shape)
                manager.install(
                    RuntimeSpec(version=version),
                    archive_override=archive,
                    sha256_override=digest,
                )
            source = root / "sample.ps1"
            source.write_text("'value'", encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                report_code = main([
                    "--home", str(home), "test", str(source),
                    "--runtime", "7.4.18", "--runtime", "7.6.4",
                    "--psscriptanalyzer", "off", "--pester", "off",
                    "--differential", "report", "--json",
                ])
            payload = json.loads(output.getvalue())
            self.assertEqual(report_code, 0)
            self.assertEqual(payload["status"], "PASS_WITH_DIFFERENCES")
            self.assertGreater(payload["differential"][0]["issue_count"], 0)

            output = StringIO()
            with redirect_stdout(output):
                strict_code = main([
                    "--home", str(home), "test", str(source),
                    "--runtime", "7.4.18", "--runtime", "7.6.4",
                    "--psscriptanalyzer", "off", "--pester", "off",
                    "--differential", "strict", "--json",
                ])
            strict_payload = json.loads(output.getvalue())
            self.assertEqual(strict_code, 1)
            self.assertEqual(strict_payload["status"], "FAIL_DIFFERENTIAL")


if __name__ == "__main__":
    unittest.main()
