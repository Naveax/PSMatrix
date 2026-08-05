import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from psmatrix.diagnostics import collect_diagnostics, report_diagnostics
from psmatrix.gate import create_gate_receipt, verify_gate_receipt
from psmatrix.models import ParseDiagnostic, RuntimeSpec, TargetReport, VerificationCheck
from psmatrix.repair import (
    RepairError,
    apply_and_validate,
    apply_bundle,
    build_repair_plan,
    propose_patch,
    rollback_transaction,
)
from psmatrix.runtime import RuntimeManager


FAKE_PWSH = r'''#!/usr/bin/env python3
import json
import sys
from pathlib import Path
args = sys.argv[1:]
if "-Command" in args:
    print("7.6.4")
    raise SystemExit(0)
harness = Path(args[args.index("-File") + 1]).name
source = Path(args[args.index("-SourcePath") + 1]) if "-SourcePath" in args else None
if harness == "parse.ps1":
    text = source.read_text(encoding="utf-8")
    broken = "BROKEN" in text
    print(json.dumps({"schema": 2, "ok": not broken, "errors": ([{"message": "fake parse error", "line": 1, "column": 1}] if broken else []), "analysis": {"commands": []}, "analyzer": {"status": "skipped"}}))
    raise SystemExit(0)
if harness == "execute.ps1":
    text = source.read_text(encoding="utf-8")
    observation = Path(args[args.index("-ObservationPath") + 1])
    observation.parent.mkdir(parents=True, exist_ok=True)
    if "FAIL_EXECUTION" in text:
        observation.write_text(json.dumps({"schema": 3, "status": "failed", "runtime": {"version": "7.6.4", "edition": "Core"}, "streams": {"success": {"count": 0}, "error": {"count": 1, "records": [{"message": "bad"}]}, "warning": {"count": 0}, "verbose": {"count": 0}, "debug": {"count": 0}, "information": {"count": 0}}, "native": {"observed": False, "last_exit_code": None}}), encoding="utf-8")
        print("failure", file=sys.stderr)
        raise SystemExit(1)
    observation.write_text(json.dumps({"schema": 3, "status": "completed", "runtime": {"version": "7.6.4", "edition": "Core"}, "streams": {"success": {"count": 1, "records": []}, "error": {"count": 0, "records": []}, "warning": {"count": 0, "records": []}, "verbose": {"count": 0, "records": []}, "debug": {"count": 0, "records": []}, "information": {"count": 0, "records": []}}, "native": {"observed": False, "last_exit_code": None}, "output_count": 1, "output_shapes": []}), encoding="utf-8")
    print("ok")
    raise SystemExit(0)
print(json.dumps({"status": "no-tests", "failed": 0}))
raise SystemExit(0)
'''


def install_fake_runtime(home: Path, root: Path):
    archive = root / "powershell-7.6.4-linux-x64.tar.gz"
    payload = FAKE_PWSH.encode("utf-8")
    with tarfile.open(archive, "w:gz") as handle:
        info = tarfile.TarInfo("pwsh")
        info.mode = 0o755
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    RuntimeManager(home).install(RuntimeSpec(version="7.6.4"), archive_override=archive, sha256_override=digest)


class DiagnosticTests(unittest.TestCase):
    def test_stable_codes_cover_parse_analyzer_and_verification(self):
        target = TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source="/project/tool.ps1",
            source_sha256="0" * 64,
            status="FAIL_VERIFICATION",
            parse_ok=False,
            parse_diagnostics=[ParseDiagnostic(message="bad token", line=2, column=3)],
            verification=[VerificationCheck(kind="file_exists", passed=False, subject="out.json")],
            analysis={"psscriptanalyzer": {"diagnostics": [{"rule_name": "AvoidAlias", "severity": "Warning", "message": "alias", "line": 4}]}}
        )
        values = collect_diagnostics([target])
        codes = {item["code"] for item in values}
        self.assertIn("PSMX1101", codes)
        self.assertIn("PSMX1701", codes)
        self.assertTrue(any(code.startswith("PSMXA-") for code in codes))
        diagnostics, summary = report_diagnostics({"targets": [target.to_dict()]})
        self.assertEqual(summary["count"], len(diagnostics))


class PatchTransactionTests(unittest.TestCase):
    def test_patch_diagnostic_codes_must_belong_to_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("BROKEN\n", encoding="utf-8")
            report = {"status": "FAIL", "targets": [{
                "runtime_id": "powershell-7.6.4-linux-x64",
                "runtime_version": "7.6.4",
                "source": str(source),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "status": "FAIL_PARSE",
                "parse_ok": False,
                "parse_diagnostics": [{"message": "bad", "line": 1, "column": 1}],
            }]}
            plan = build_repair_plan(report, root, validation_argv=["test", "tool.ps1"])
            with self.assertRaises(RepairError):
                propose_patch(
                    root,
                    {"files": [{"path": "tool.ps1", "edits": [{
                        "old": "BROKEN", "new": "'ok'",
                        "diagnostic_codes": ["PSMX9999"],
                    }]}]},
                    plan=plan,
                )
            bundle = propose_patch(
                root,
                {"files": [{"path": "tool.ps1", "edits": [{"old": "BROKEN", "new": "'ok'"}]}]},
                plan=plan,
            )
            self.assertEqual(bundle["actions"][0]["edits"][0]["diagnostic_codes"], ["PSMX1101"])

    def test_patch_is_hash_bound_and_rollback_restores_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'old'\n", encoding="utf-8")
            report = {"status": "FAIL", "targets": [{
                "runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4",
                "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "status": "FAIL_PARSE", "parse_ok": False,
                "parse_diagnostics": [{"message": "bad", "line": 1, "column": 1}],
            }]}
            plan = build_repair_plan(report, root, validation_argv=["test", "tool.ps1"])
            bundle = propose_patch(root, {"files": [{"path": "tool.ps1", "edits": [{"old": "'old'", "new": "'new'", "diagnostic_codes": ["PSMX1101"]}]}]}, plan=plan)
            transaction_id, applied, transaction = apply_bundle(root, bundle, root / ".tx")
            self.assertTrue(transaction_id.startswith("rtx_"))
            self.assertEqual(source.read_text(encoding="utf-8"), "'new'\n")
            self.assertIn("-'old'", applied[0].diff)
            rollback_transaction(root, transaction)
            self.assertEqual(source.read_text(encoding="utf-8"), "'old'\n")

            source.write_text("changed", encoding="utf-8")
            with self.assertRaises(RepairError):
                apply_bundle(root, bundle, root / ".tx2")

    def test_apply_and_validate_accepts_pass_and_rolls_back_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            project = root / "project"
            project.mkdir()
            install_fake_runtime(home, root)
            source = project / "tool.ps1"
            source.write_text("BROKEN\n", encoding="utf-8")
            report = {"status": "FAIL", "targets": [{
                "runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4",
                "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "status": "FAIL_PARSE", "parse_ok": False,
                "parse_diagnostics": [{"message": "bad", "line": 1, "column": 1}],
            }]}
            validation = ["test", "tool.ps1", "--runtime", "7.6.4", "--psscriptanalyzer", "off", "--pester", "off"]
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(project, {"files": [{"path": "tool.ps1", "edits": [{"old": "BROKEN", "new": "'ok'"}]}]}, plan=plan)
            result = apply_and_validate(project, home, bundle, validation, session_path=project / ".psmatrix/session.json")
            self.assertTrue(result["accepted"], result)
            self.assertEqual(source.read_text(encoding="utf-8"), "'ok'\n")

            second_report = {"status": "FAIL", "targets": [{
                "runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4",
                "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "status": "FAIL_VERIFICATION", "parse_ok": True,
                "verification": [{"kind": "test", "passed": False, "subject": "behavior"}],
            }]}
            second_plan = build_repair_plan(second_report, project, validation_argv=validation)
            fail_bundle = propose_patch(project, {"files": [{"path": "tool.ps1", "edits": [{"old": "'ok'", "new": "FAIL_EXECUTION"}]}]}, plan=second_plan)
            failed = apply_and_validate(project, home, fail_bundle, validation, session_path=project / ".psmatrix/fail-session.json")
            self.assertFalse(failed["accepted"])
            self.assertEqual(source.read_text(encoding="utf-8"), "'ok'\n")
            self.assertEqual(failed["attempt"]["rolled_back"], ["tool.ps1"])

    def test_validation_digest_and_baseline_coverage_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            project = root / "project"
            project.mkdir()
            install_fake_runtime(home, root)
            first = project / "first.ps1"
            second = project / "second.ps1"
            first.write_text("BROKEN\n", encoding="utf-8")
            second.write_text("'ok'\n", encoding="utf-8")
            report = {"status": "FAIL", "targets": [
                {"runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4", "source": str(first), "source_sha256": hashlib.sha256(first.read_bytes()).hexdigest(), "status": "FAIL_PARSE", "parse_ok": False, "parse_diagnostics": [{"message": "bad", "line": 1, "column": 1}]},
                {"runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4", "source": str(second), "source_sha256": hashlib.sha256(second.read_bytes()).hexdigest(), "status": "PASS", "parse_ok": True},
            ]}
            validation = ["test", "first.ps1", "--runtime", "7.6.4", "--psscriptanalyzer", "off", "--pester", "off"]
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(project, {"files": [{"path": "first.ps1", "edits": [{"old": "BROKEN", "new": "'ok'"}]}]}, plan=plan)
            with self.assertRaises(RepairError):
                apply_and_validate(project, home, bundle, validation + ["--cache", "off"], session_path=project / ".psmatrix/mismatch.json")
            self.assertEqual(first.read_text(encoding="utf-8"), "BROKEN\n")

            result = apply_and_validate(project, home, bundle, validation, session_path=project / ".psmatrix/coverage.json")
            self.assertFalse(result["accepted"])
            self.assertIn("omitted baseline targets", result["attempt"]["error"])
            self.assertEqual(first.read_text(encoding="utf-8"), "BROKEN\n")

    def test_attempt_limit_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            project = root / "project"
            project.mkdir()
            install_fake_runtime(home, root)
            source = project / "tool.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            validation = ["test", "tool.ps1", "--runtime", "7.6.4", "--psscriptanalyzer", "off", "--pester", "off", "--env", "SECRET=top-secret"]
            report = {"status": "FAIL", "targets": [{"runtime_id": "powershell-7.6.4-linux-x64", "runtime_version": "7.6.4", "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "status": "FAIL_VERIFICATION", "parse_ok": True, "verification": [{"kind": "test", "passed": False, "subject": "behavior"}]}]}
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(project, {"files": [{"path": "tool.ps1", "edits": [{"old": "'ok'", "new": "FAIL_EXECUTION"}]}]}, plan=plan)
            session = project / ".psmatrix/session.json"
            result = apply_and_validate(project, home, bundle, validation, session_path=session, max_attempts=1)
            self.assertFalse(result["accepted"])
            serialized = session.read_text(encoding="utf-8")
            self.assertNotIn("top-secret", serialized)
            self.assertIn("<redacted>", serialized)
            with self.assertRaises(RepairError):
                apply_and_validate(project, home, bundle, validation, session_path=session, max_attempts=1)


class GateTests(unittest.TestCase):
    def test_signed_gate_rejects_source_changed_after_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            report = {
                "tool_version": "0.8.0", "status": "PASS",
                "targets": [{"source": str(source), "runtime_id": "powershell-7.6.4-linux-x64"}],
            }
            receipt = create_gate_receipt(report, root, root / "home")
            valid = verify_gate_receipt(receipt, root, root / "home")
            self.assertTrue(valid["valid"])
            source.write_text("'changed'", encoding="utf-8")
            stale = verify_gate_receipt(receipt, root, root / "home")
            self.assertFalse(stale["valid"])
            self.assertEqual(stale["stale"][0]["reason"], "sha256 changed")
            receipt["report_status"] = "FAIL"
            with self.assertRaises(Exception):
                verify_gate_receipt(receipt, root, root / "home")


if __name__ == "__main__":
    unittest.main()
