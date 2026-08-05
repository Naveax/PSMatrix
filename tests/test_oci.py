import json
import os
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from psmatrix.cli import main
from psmatrix.models import RuntimeSpec
from psmatrix.oci import OciRuntimeManager, validate_image_reference


_FAKE_ENGINE = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
log = os.environ.get("PSMATRIX_FAKE_ENGINE_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")
if not args:
    raise SystemExit(2)
if args[0] == "version":
    print("fake engine 1.0")
    raise SystemExit(0)
if args[0] == "pull":
    print(args[-1])
    raise SystemExit(0)
if args[:2] == ["image", "inspect"]:
    if os.environ.get("PSMATRIX_FAKE_NO_DIGEST") == "1":
        print("[]")
    else:
        print(json.dumps(["mcr.microsoft.com/powershell@sha256:" + "a" * 64]))
    raise SystemExit(0)
if args[0] == "rm":
    raise SystemExit(0)
if args[0] != "run":
    raise SystemExit(3)

mount_root = None
for i, value in enumerate(args):
    if value == "--mount" and i + 1 < len(args):
        spec = args[i + 1]
        for item in spec.split(","):
            if item.startswith("src="):
                mount_root = pathlib.Path(item[4:])

def host_path(value):
    if mount_root is not None and value.startswith("/workspace/"):
        return mount_root / value[len("/workspace/"):]
    return pathlib.Path(value)

if "-Command" in args:
    print(os.environ.get("PSMATRIX_FAKE_VERSION", "6.0.5"))
    raise SystemExit(0)
if "-File" not in args:
    raise SystemExit(4)
harness = pathlib.Path(args[args.index("-File") + 1]).name
if harness == "parse.ps1":
    print(json.dumps({
        "schema": 2,
        "ok": True,
        "errors": [],
        "analysis": {"commands": [], "types": [], "functions": [], "classes": []},
        "analyzer": {"status": "skipped", "diagnostics": []},
    }))
    raise SystemExit(0)
if harness == "execute.ps1":
    observation = host_path(args[args.index("-ObservationPath") + 1])
    observation.parent.mkdir(parents=True, exist_ok=True)
    observation.write_text(json.dumps({
        "schema": 1,
        "status": "completed",
        "runtime": {"version": os.environ.get("PSMATRIX_FAKE_VERSION", "6.0.5"), "edition": "Core"},
        "output_count": 1,
        "output_truncated": False,
        "output_shapes": [{"index": 0, "base_type": "System.String", "pstype_names": ["System.String"], "properties": []}],
        "error": None,
    }), encoding="utf-8")
    print("oci-ok")
    raise SystemExit(0)
if harness == "pester.ps1":
    print(json.dumps({"status": "no-tests", "failed": 0, "passed": 0, "skipped": 0}))
    raise SystemExit(0)
raise SystemExit(5)
'''


class OciRuntimeTests(unittest.TestCase):
    def _engine(self, root: Path) -> Path:
        engine = root / "docker"
        engine.write_text(_FAKE_ENGINE, encoding="utf-8")
        engine.chmod(0o755)
        return engine

    def test_image_reference_validation(self):
        self.assertEqual(
            validate_image_reference("mcr.microsoft.com/powershell:6.0.5-ubuntu-16.04"),
            "mcr.microsoft.com/powershell:6.0.5-ubuntu-16.04",
        )
        with self.assertRaises(Exception):
            validate_image_reference("bad image; rm -rf /")

    def test_install_pins_digest_and_probes_exact_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._engine(root)
            manager = OciRuntimeManager(root / "home")
            spec = RuntimeSpec(version="6.0.5")
            with patch.dict(
                os.environ,
                {
                    "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                    "PSMATRIX_FAKE_VERSION": "6.0.5",
                },
                clear=False,
            ):
                payload = manager.install(spec, engine="docker")
                self.assertTrue(payload["verified_digest"])
                self.assertTrue(payload["image_pinned"].endswith("@sha256:" + "a" * 64))
                wrapper = manager.wrapper_path(spec).read_text(encoding="utf-8")
                self.assertIn("PSMATRIX_STDIN_ENABLED", wrapper)
                self.assertIn("command.append('-i')", wrapper)
                self.assertIn("PSMATRIX_USER_ENV_NAMES", wrapper)
                self.assertIn("command.extend(['--env', key])", wrapper)
                probe = manager.probe(spec, engine="docker")
                self.assertEqual(probe["detected_version"], "6.0.5")
                self.assertTrue(manager.wrapper_path(spec).is_file())


    def test_mutable_local_tag_requires_explicit_trust(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._engine(root)
            manager = OciRuntimeManager(root / "home")
            env = {
                "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                "PSMATRIX_FAKE_VERSION": "6.0.5",
                "PSMATRIX_FAKE_NO_DIGEST": "1",
            }
            with patch.dict(os.environ, env, clear=False):
                with self.assertRaises(Exception):
                    manager.install(
                        RuntimeSpec(version="6.0.5"),
                        engine="docker",
                        pull=False,
                    )
                payload = manager.install(
                    RuntimeSpec(version="6.0.5"),
                    engine="docker",
                    pull=False,
                    trust_local=True,
                )
            self.assertTrue(payload["trusted_local"])
            self.assertFalse(payload["verified_digest"])

    def test_version_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._engine(root)
            manager = OciRuntimeManager(root / "home")
            with patch.dict(
                os.environ,
                {
                    "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                    "PSMATRIX_FAKE_VERSION": "7.6.4",
                },
                clear=False,
            ):
                with self.assertRaises(Exception):
                    manager.install(RuntimeSpec(version="6.0.5"), engine="docker")

    def test_cli_executes_registered_oci_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            engine = self._engine(root)
            home = root / "home"
            source = root / "sample.ps1"
            source.write_text("'oci-ok'", encoding="utf-8")
            log = root / "engine.log"
            env = {
                "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                "PSMATRIX_FAKE_VERSION": "6.0.5",
                "PSMATRIX_FAKE_ENGINE_LOG": str(log),
            }
            with patch.dict(os.environ, env, clear=False):
                manager = OciRuntimeManager(home)
                manager.install(RuntimeSpec(version="6.0.5"), engine="docker")
                output = StringIO()
                with redirect_stdout(output):
                    code = main([
                        "--home", str(home),
                        "test", str(source),
                        "--runtime", "6.0.5",
                        "--backend", "oci",
                        "--container-engine", "docker",
                        "--psscriptanalyzer", "off",
                        "--pester", "off",
                        "--json",
                    ])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(payload["status"], "PASS")
            target = payload["targets"][0]
            self.assertEqual(target["runtime"]["backend"], "oci")
            self.assertEqual(target["sandbox"]["backend"], "oci-container")
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            run_calls = [call for call in calls if call and call[0] == "run"]
            self.assertTrue(any("--read-only" in call for call in run_calls))
            self.assertTrue(any("--cap-drop=ALL" in call for call in run_calls))
            self.assertTrue(any("no-new-privileges" in call for call in run_calls))
            self.assertTrue(any("none" in call for call in run_calls))


if __name__ == "__main__":
    unittest.main()
