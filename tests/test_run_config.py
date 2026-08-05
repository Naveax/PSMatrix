import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from psmatrix.run_config import (
    RunConfigurationError,
    materialize_fixtures,
    resolve_execution_profile,
    stage_hooks,
)


class RunConfigurationTests(unittest.TestCase):
    def test_manifest_and_cli_inputs_merge_without_exposing_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("param($Name)", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data", encoding="utf-8")
            hook = root / "setup.ps1"
            hook.write_text("'setup'", encoding="utf-8")
            digest = hashlib.sha256(hook.read_bytes()).hexdigest()
            (root / "script.ps1.psmatrix.json").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "run": {
                            "arguments": ["manifest-arg"],
                            "parameters": {"Name": "manifest"},
                            "environment": {"DEMO": "secret-value"},
                            "stdin": {"text": "input"},
                            "fixtures": [
                                {"source": "fixture.txt", "destination": "inputs/data.txt"}
                            ],
                            "setup": [{"path": "setup.ps1", "sha256": digest}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            profile = resolve_execution_profile(
                source,
                cli_arguments=("cli-arg",),
                cli_parameters=(("Name", "cli"),),
                cli_environment=(("OTHER", "value"),),
            )
            self.assertEqual(profile.arguments, ["manifest-arg", "cli-arg"])
            self.assertEqual(profile.parameters["Name"], "cli")
            self.assertEqual(profile.environment["DEMO"], "secret-value")
            self.assertEqual(profile.stdin_data, b"input")
            report = profile.redacted_report()
            self.assertNotIn("secret-value", json.dumps(report))
            self.assertEqual(report["fixtures"][0]["destination"], "inputs/data.txt")

    def test_rejects_reserved_environment_and_unsafe_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data", encoding="utf-8")
            with self.assertRaises(RunConfigurationError):
                resolve_execution_profile(source, cli_environment=(("PATH", "/tmp"),))
            with self.assertRaises(RunConfigurationError):
                resolve_execution_profile(
                    source,
                    cli_fixtures=((str(fixture), "../escape.txt"),),
                )

    def test_rejects_symlink_components(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            real = root / "real.txt"
            real.write_text("data", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(real)
            with self.assertRaises(RunConfigurationError):
                resolve_execution_profile(source, cli_fixtures=((str(link), None),))

    def test_materializes_fixture_and_detects_collision(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data", encoding="utf-8")
            profile = resolve_execution_profile(
                source,
                cli_fixtures=((str(fixture), "input/data.txt"),),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            staged = materialize_fixtures(workspace, profile.fixtures)
            self.assertEqual((workspace / "input/data.txt").read_text(), "data")
            self.assertEqual(len(staged), 1)
            (workspace / "input/data.txt").write_text("changed")
            with self.assertRaises(RunConfigurationError):
                materialize_fixtures(workspace, profile.fixtures)

    def test_rejects_symlinked_fixture_destination_and_internal_hook_root(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data", encoding="utf-8")
            hook = root / "setup.ps1"
            hook.write_text("'setup'", encoding="utf-8")
            profile = resolve_execution_profile(
                source,
                cli_fixtures=((str(fixture), "linked/data.txt"),),
                cli_setup=(str(hook),),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            real = workspace / "real"
            real.mkdir()
            (workspace / "linked").symlink_to(real, target_is_directory=True)
            with self.assertRaises(RunConfigurationError):
                materialize_fixtures(workspace, profile.fixtures)

            (workspace / "linked").unlink()
            internal_target = workspace / "internal-target"
            internal_target.mkdir()
            (workspace / ".psmatrix-internal").symlink_to(
                internal_target, target_is_directory=True
            )
            with self.assertRaises(RunConfigurationError):
                stage_hooks(workspace, profile.setup, "setup")

    def test_rejects_symlinked_default_lockfile(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            real = root / "real-lock.json"
            real.write_text('{"schema":1,"powershell_modules":[],"native_commands":[]}', encoding="utf-8")
            (root / "psmatrix.lock.json").symlink_to(real)
            with self.assertRaises(RunConfigurationError):
                resolve_execution_profile(source)


if __name__ == "__main__":
    unittest.main()
