import hashlib
import io
import json
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions, ScriptRunner
from psmatrix.runtime import RuntimeManager


FAKE_PWSH = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if "-Command" in args:
    print("7.6.4")
    raise SystemExit(0)

try:
    file_index = args.index("-File")
    harness = Path(args[file_index + 1]).name
except (ValueError, IndexError):
    print("unsupported fake invocation", file=sys.stderr)
    raise SystemExit(2)
source = None
if "-SourcePath" in args:
    source = Path(args[args.index("-SourcePath") + 1])

if harness == "parse.ps1":
    text = source.read_text(encoding="utf-8")
    if "BROKEN_PARSE" in text:
        print(json.dumps({"schema": 1, "ok": False, "errors": [{"message": "fake parse error", "line": 1, "column": 1}]}))
    else:
        print(json.dumps({"schema": 1, "ok": True, "errors": []}))
    raise SystemExit(0)

if harness == "dependencies.ps1":
    lock_path = Path(args[args.index("-LockPath") + 1])
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    checks = []
    for item in payload.get("native_commands", []):
        expected = item.get("expected_version")
        passed = expected == "fake-1.0"
        checks.append({
            "kind": "native_command",
            "name": item.get("name"),
            "passed": passed,
            "expected_version": expected,
            "actual_version": "fake-1.0",
            "required": item.get("required", True),
        })
    failed = sum(1 for item in checks if not item["passed"])
    print(json.dumps({"schema": 1, "status": "satisfied" if failed == 0 else "unsatisfied", "failed": failed, "checks": checks}))
    raise SystemExit(0)

if harness == "hook.ps1":
    hook_path = Path(args[args.index("-HookPath") + 1])
    phase = args[args.index("-Phase") + 1]
    text = hook_path.read_text(encoding="utf-8")
    if "FAIL_HOOK" in text:
        print(json.dumps({"schema": 1, "status": "failed", "phase": phase, "hook": str(hook_path)}))
        raise SystemExit(1)
    Path.cwd().joinpath(phase + ".marker").write_text("ok", encoding="utf-8")
    print(json.dumps({"schema": 1, "status": "completed", "phase": phase, "hook": str(hook_path)}))
    raise SystemExit(0)

if harness == "execute.ps1":
    text = source.read_text(encoding="utf-8")
    observation = None
    if "-ObservationPath" in args:
        observation = Path(args[args.index("-ObservationPath") + 1])
    if "FAIL_EXECUTION" in text:
        if observation:
            observation.parent.mkdir(parents=True, exist_ok=True)
            observation.write_text(json.dumps({
                "schema": 1,
                "runtime": {"version": "7.6.4", "edition": "Core"},
                "output_count": 0,
                "output_truncated": False,
                "output_shapes": [],
                "error": {"exception_type": "Fake.Error", "category": "NotSpecified"},
            }), encoding="utf-8")
        print("fake execution failure", file=sys.stderr)
        raise SystemExit(1)
    payload = {"message": "PSMatrix works", "edition": "Core", "version": "7.6.4"}
    if "INPUT_ECHO" in text:
        arguments = json.loads(args[args.index("-ArgumentsJson") + 1])
        parameters = json.loads(args[args.index("-ParametersJson") + 1])
        payload.update({
            "arguments": arguments,
            "parameters": parameters,
            "environment": os.environ.get("DEMO_INPUT"),
            "stdin": sys.stdin.buffer.read().decode("utf-8"),
            "fixture": Path.cwd().joinpath("fixtures/input.txt").read_text(encoding="utf-8"),
            "setup": Path.cwd().joinpath("setup.marker").is_file(),
        })
    Path.cwd().joinpath("result.json").write_text(json.dumps(payload), encoding="utf-8")
    if observation:
        observation.parent.mkdir(parents=True, exist_ok=True)
        observation.write_text(json.dumps({
            "schema": 1,
            "runtime": {"version": "7.6.4", "edition": "Core"},
            "output_count": 1,
            "output_truncated": False,
            "output_shapes": [{
                "index": 0,
                "base_type": "System.String",
                "pstype_names": ["System.String"],
                "properties": [],
            }],
            "error": None,
        }), encoding="utf-8")
    print("PSMatrix works")
    raise SystemExit(0)

print("unknown harness", file=sys.stderr)
raise SystemExit(2)
'''


class IntegrationTests(unittest.TestCase):
    def make_runtime_archive(self, root: Path) -> tuple[Path, str]:
        archive = root / "fake-powershell.tar.gz"
        payload = FAKE_PWSH.encode("utf-8")
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("pwsh")
            info.mode = 0o755
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        return archive, digest

    def write_example(self, root: Path, broken=False) -> Path:
        source = root / "example.ps1"
        source.write_text("BROKEN_PARSE" if broken else "'test'", encoding="utf-8")
        contract = {
            "schema": 1,
            "expect": {
                "exit_code": 0,
                "stderr_empty": True,
                "stdout_contains": ["PSMatrix works"],
                "files": [{"path": "result.json", "exists": True, "valid_json": True}],
                "json": [{"path": "result.json", "property": "message", "equals": "PSMatrix works"}],
            },
        }
        source.with_name(source.name + ".psmatrix.json").write_text(
            json.dumps(contract), encoding="utf-8"
        )
        return source

    def test_local_archive_install_and_full_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            archive, digest = self.make_runtime_archive(root)
            installation = manager.install(
                spec, archive_override=archive, sha256_override=digest
            )
            self.assertTrue(installation.executable.is_file())

            source_dir = root / "project"
            source_dir.mkdir()
            source = self.write_example(source_dir)
            package_root = Path(__file__).resolve().parents[1] / "src" / "psmatrix"
            report = ScriptRunner(manager, package_root).run(
                source, spec, RunOptions(timeout_seconds=5)
            )
            self.assertEqual(report.status, "PASS")
            self.assertTrue(all(check.passed for check in report.verification))
            self.assertTrue(any(change.path == "result.json" for change in report.file_changes))
            self.assertEqual(report.observation["status"], "completed")
            self.assertEqual(report.observation["output_count"], 1)
            self.assertEqual(
                report.observation["output_shapes"][0]["base_type"], "System.String"
            )
            self.assertFalse(
                any(change.path.startswith(".psmatrix-internal/") for change in report.file_changes)
            )

    def test_parse_failure_stops_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            archive, digest = self.make_runtime_archive(root)
            manager.install(spec, archive_override=archive, sha256_override=digest)
            source_dir = root / "project"
            source_dir.mkdir()
            source = self.write_example(source_dir, broken=True)
            package_root = Path(__file__).resolve().parents[1] / "src" / "psmatrix"
            report = ScriptRunner(manager, package_root).run(
                source, spec, RunOptions(timeout_seconds=5)
            )
            self.assertEqual(report.status, "FAIL_PARSE")
            self.assertFalse(report.parse_ok)

    def _installed_runner(self, root: Path):
        manager = RuntimeManager(root / "home")
        spec = RuntimeSpec(version="7.6.4", arch="x64")
        archive, digest = self.make_runtime_archive(root)
        manager.install(spec, archive_override=archive, sha256_override=digest)
        package_root = Path(__file__).resolve().parents[1] / "src" / "psmatrix"
        return manager, spec, ScriptRunner(manager, package_root)

    def test_required_dependency_lock_is_enforced_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, spec, runner = self._installed_runner(root)
            project = root / "project"
            project.mkdir()
            source = self.write_example(project)
            report = runner.run(
                source,
                spec,
                RunOptions(timeout_seconds=5, dependency_policy="required"),
            )
            self.assertEqual(report.status, "FAIL_DEPENDENCY")
            self.assertIsNone(report.execution)

    def test_dependency_mismatch_stops_before_setup_and_script(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, spec, runner = self._installed_runner(root)
            project = root / "project"
            project.mkdir()
            source = self.write_example(project)
            (project / "psmatrix.lock.json").write_text(json.dumps({
                "schema": 1,
                "powershell_modules": [],
                "native_commands": [{
                    "name": "fake",
                    "command": "fake",
                    "version_args": ["--version"],
                    "version_pattern": "(?<version>.+)",
                    "expected_version": "wrong",
                    "required": True,
                }],
            }), encoding="utf-8")
            report = runner.run(
                source,
                spec,
                RunOptions(timeout_seconds=5, dependency_policy="required"),
            )
            self.assertEqual(report.status, "FAIL_DEPENDENCY")
            self.assertEqual(report.dependencies["status"], "unsatisfied")
            self.assertIsNotNone(report.execution)
            self.assertTrue(any(str(item).endswith("parse.ps1") for item in report.execution.command))

    def test_inputs_and_hooks_flow_with_redacted_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, spec, runner = self._installed_runner(root)
            project = root / "project"
            project.mkdir()
            source = self.write_example(project)
            source.write_text("INPUT_ECHO", encoding="utf-8")
            fixture = project / "fixture.txt"
            fixture.write_text("fixture-data", encoding="utf-8")
            setup = project / "setup.ps1"
            setup.write_text("'setup'", encoding="utf-8")
            teardown = project / "teardown.ps1"
            teardown.write_text("'teardown'", encoding="utf-8")
            sidecar_path = project / "example.ps1.psmatrix.json"
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            sidecar["expect"]["json"].extend([
                {"path": "result.json", "property": "arguments.0", "equals": "alpha"},
                {"path": "result.json", "property": "arguments.1", "equals": "beta"},
                {"path": "result.json", "property": "parameters.Count", "equals": 3},
                {"path": "result.json", "property": "environment", "equals": "super-secret"},
                {"path": "result.json", "property": "stdin", "equals": "stdin-data"},
                {"path": "result.json", "property": "fixture", "equals": "fixture-data"},
                {"path": "result.json", "property": "setup", "equals": True},
            ])
            sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
            (project / "psmatrix.lock.json").write_text(json.dumps({
                "schema": 1,
                "powershell_modules": [],
                "native_commands": [{
                    "name": "fake",
                    "command": "fake",
                    "version_args": ["--version"],
                    "version_pattern": "(?<version>.+)",
                    "expected_version": "fake-1.0",
                    "required": True,
                }],
            }), encoding="utf-8")
            report = runner.run(
                source,
                spec,
                RunOptions(
                    timeout_seconds=5,
                    arguments=("alpha", "beta"),
                    parameters=(("Count", 3),),
                    environment=(("DEMO_INPUT", "super-secret"),),
                    stdin_data=b"stdin-data",
                    stdin_source="test",
                    fixtures=((str(fixture), "fixtures/input.txt"),),
                    setup_scripts=(str(setup),),
                    teardown_scripts=(str(teardown),),
                    dependency_policy="required",
                ),
            )
            self.assertEqual(report.status, "PASS")
            self.assertEqual(report.dependencies["status"], "satisfied")
            self.assertEqual(len(report.hooks["setup"]), 1)
            self.assertEqual(len(report.hooks["teardown"]), 1)
            serialized = json.dumps(report.inputs)
            self.assertNotIn("super-secret", serialized)
            self.assertNotIn("stdin-data", serialized)
            self.assertEqual(report.inputs["arguments"]["count"], 2)
            self.assertTrue(all(check.passed for check in report.verification))

    def test_setup_and_teardown_failures_have_distinct_statuses(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, spec, runner = self._installed_runner(root)
            project = root / "project"
            project.mkdir()
            source = self.write_example(project)
            setup = project / "setup.ps1"
            setup.write_text("FAIL_HOOK", encoding="utf-8")
            report = runner.run(
                source, spec, RunOptions(timeout_seconds=5, setup_scripts=(str(setup),))
            )
            self.assertEqual(report.status, "FAIL_SETUP")
            self.assertIsNotNone(report.execution)
            self.assertTrue(any(str(item).endswith("parse.ps1") for item in report.execution.command))

            teardown = project / "teardown.ps1"
            teardown.write_text("FAIL_HOOK", encoding="utf-8")
            report = runner.run(
                source, spec, RunOptions(timeout_seconds=5, teardown_scripts=(str(teardown),))
            )
            self.assertEqual(report.status, "FAIL_TEARDOWN")
            self.assertIsNotNone(report.execution)

class SandboxProjectCopyHardeningTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "Unix sockets unavailable")
    def test_project_copy_skips_socket_and_other_non_regular_files(self):
        import socket
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            (source / "tool.ps1").write_text("'ok'", encoding="utf-8")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(source / "agent.sock"))
                ScriptRunner._copy_project(source, destination)
            finally:
                sock.close()
            self.assertTrue((destination / "tool.ps1").is_file())
            self.assertFalse((destination / "agent.sock").exists())
