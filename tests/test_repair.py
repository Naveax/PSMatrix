import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.diagnostics import collect_diagnostics, report_diagnostics
from psmatrix.gate import create_gate_receipt, verify_gate_receipt
from psmatrix.models import ParseDiagnostic, TargetReport, VerificationCheck
from psmatrix.repair import (
    RepairError,
    apply_and_validate,
    apply_bundle,
    build_repair_plan,
    propose_patch,
    rollback_transaction,
)


RUNTIME_ID = "powershell-7.6.4-linux-x64"
RUNTIME_VERSION = "7.6.4"


def validation_target(source: Path, *, status: str = "PASS") -> dict:
    return {
        "runtime_id": RUNTIME_ID,
        "runtime_version": RUNTIME_VERSION,
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "status": status,
        "parse_ok": status != "FAIL_PARSE",
    }


class DiagnosticTests(unittest.TestCase):
    def test_stable_codes_cover_parse_analyzer_and_verification(self):
        target = TargetReport(
            runtime_id=RUNTIME_ID,
            runtime_version=RUNTIME_VERSION,
            source="/project/tool.ps1",
            source_sha256="0" * 64,
            status="FAIL_VERIFICATION",
            parse_ok=False,
            parse_diagnostics=[ParseDiagnostic(message="bad token", line=2, column=3)],
            verification=[VerificationCheck(kind="file_exists", passed=False, subject="out.json")],
            analysis={
                "psscriptanalyzer": {
                    "diagnostics": [
                        {
                            "rule_name": "AvoidAlias",
                            "severity": "Warning",
                            "message": "alias",
                            "line": 4,
                        }
                    ]
                }
            },
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
            report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(source, status="FAIL_PARSE"),
                        "parse_diagnostics": [
                            {"message": "bad", "line": 1, "column": 1}
                        ],
                    }
                ],
            }
            plan = build_repair_plan(
                report, root, validation_argv=["test", "tool.ps1"]
            )
            with self.assertRaises(RepairError):
                propose_patch(
                    root,
                    {
                        "files": [
                            {
                                "path": "tool.ps1",
                                "edits": [
                                    {
                                        "old": "BROKEN",
                                        "new": "'ok'",
                                        "diagnostic_codes": ["PSMX9999"],
                                    }
                                ],
                            }
                        ]
                    },
                    plan=plan,
                )
            bundle = propose_patch(
                root,
                {
                    "files": [
                        {
                            "path": "tool.ps1",
                            "edits": [{"old": "BROKEN", "new": "'ok'"}],
                        }
                    ]
                },
                plan=plan,
            )
            self.assertEqual(
                bundle["actions"][0]["edits"][0]["diagnostic_codes"],
                ["PSMX1101"],
            )

    def test_patch_is_hash_bound_and_rollback_restores_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'old'\n", encoding="utf-8")
            report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(source, status="FAIL_PARSE"),
                        "parse_diagnostics": [
                            {"message": "bad", "line": 1, "column": 1}
                        ],
                    }
                ],
            }
            plan = build_repair_plan(
                report, root, validation_argv=["test", "tool.ps1"]
            )
            bundle = propose_patch(
                root,
                {
                    "files": [
                        {
                            "path": "tool.ps1",
                            "edits": [
                                {
                                    "old": "'old'",
                                    "new": "'new'",
                                    "diagnostic_codes": ["PSMX1101"],
                                }
                            ],
                        }
                    ]
                },
                plan=plan,
            )
            transaction_id, applied, transaction = apply_bundle(
                root, bundle, root / ".tx"
            )
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
            source = project / "tool.ps1"
            source.write_text("BROKEN\n", encoding="utf-8")
            report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(source, status="FAIL_PARSE"),
                        "parse_diagnostics": [
                            {"message": "bad", "line": 1, "column": 1}
                        ],
                    }
                ],
            }
            validation = [
                "test",
                "tool.ps1",
                "--runtime",
                RUNTIME_VERSION,
                "--psscriptanalyzer",
                "off",
                "--pester",
                "off",
            ]
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(
                project,
                {
                    "files": [
                        {
                            "path": "tool.ps1",
                            "edits": [{"old": "BROKEN", "new": "'ok'"}],
                        }
                    ]
                },
                plan=plan,
            )
            pass_report = {
                "status": "PASS",
                "targets": [validation_target(source, status="PASS")],
            }
            with patch(
                "psmatrix.repair.run_validation",
                return_value=(0, pass_report, "validation-pass", ""),
            ) as validation_call:
                result = apply_and_validate(
                    project,
                    home,
                    bundle,
                    validation,
                    session_path=project / ".psmatrix/session.json",
                )
            validation_call.assert_called_once()
            self.assertTrue(result["accepted"], result)
            self.assertEqual(source.read_text(encoding="utf-8"), "'ok'\n")

            second_report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(source, status="FAIL_VERIFICATION"),
                        "verification": [
                            {"kind": "test", "passed": False, "subject": "behavior"}
                        ],
                    }
                ],
            }
            second_plan = build_repair_plan(
                second_report, project, validation_argv=validation
            )
            fail_bundle = propose_patch(
                project,
                {
                    "files": [
                        {
                            "path": "tool.ps1",
                            "edits": [
                                {"old": "'ok'", "new": "FAIL_EXECUTION"}
                            ],
                        }
                    ]
                },
                plan=second_plan,
            )
            fail_validation_report = {
                "status": "FAIL",
                "targets": [validation_target(source, status="FAIL_EXECUTION")],
            }
            with patch(
                "psmatrix.repair.run_validation",
                return_value=(1, fail_validation_report, "", "failure"),
            ):
                failed = apply_and_validate(
                    project,
                    home,
                    fail_bundle,
                    validation,
                    session_path=project / ".psmatrix/fail-session.json",
                )
            self.assertFalse(failed["accepted"])
            self.assertEqual(source.read_text(encoding="utf-8"), "'ok'\n")
            self.assertEqual(failed["attempt"]["rolled_back"], ["tool.ps1"])

    def test_validation_digest_and_baseline_coverage_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            project = root / "project"
            project.mkdir()
            first = project / "first.ps1"
            second = project / "second.ps1"
            first.write_text("BROKEN\n", encoding="utf-8")
            second.write_text("'ok'\n", encoding="utf-8")
            report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(first, status="FAIL_PARSE"),
                        "parse_diagnostics": [
                            {"message": "bad", "line": 1, "column": 1}
                        ],
                    },
                    validation_target(second, status="PASS"),
                ],
            }
            validation = [
                "test",
                "first.ps1",
                "--runtime",
                RUNTIME_VERSION,
                "--psscriptanalyzer",
                "off",
                "--pester",
                "off",
            ]
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(
                project,
                {
                    "files": [
                        {
                            "path": "first.ps1",
                            "edits": [{"old": "BROKEN", "new": "'ok'"}],
                        }
                    ]
                },
                plan=plan,
            )
            with patch("psmatrix.repair.run_validation") as validation_call:
                with self.assertRaises(RepairError):
                    apply_and_validate(
                        project,
                        home,
                        bundle,
                        validation + ["--cache", "off"],
                        session_path=project / ".psmatrix/mismatch.json",
                    )
                validation_call.assert_not_called()
            self.assertEqual(first.read_text(encoding="utf-8"), "BROKEN\n")

            coverage_report = {
                "status": "PASS",
                "targets": [validation_target(first, status="PASS")],
            }
            with patch(
                "psmatrix.repair.run_validation",
                return_value=(0, coverage_report, "", ""),
            ):
                result = apply_and_validate(
                    project,
                    home,
                    bundle,
                    validation,
                    session_path=project / ".psmatrix/coverage.json",
                )
            self.assertFalse(result["accepted"])
            self.assertIn("omitted baseline targets", result["attempt"]["error"])
            self.assertEqual(first.read_text(encoding="utf-8"), "BROKEN\n")
            self.assertEqual(result["attempt"]["rolled_back"], ["first.ps1"])

    def test_attempt_limit_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            validation = [
                "test",
                "tool.ps1",
                "--runtime",
                RUNTIME_VERSION,
                "--psscriptanalyzer",
                "off",
                "--pester",
                "off",
                "--env",
                "SECRET=top-secret",
            ]
            report = {
                "status": "FAIL",
                "targets": [
                    {
                        **validation_target(source, status="FAIL_VERIFICATION"),
                        "verification": [
                            {"kind": "test", "passed": False, "subject": "behavior"}
                        ],
                    }
                ],
            }
            plan = build_repair_plan(report, project, validation_argv=validation)
            bundle = propose_patch(
                project,
                {
                    "files": [
                        {
                            "path": "tool.ps1",
                            "edits": [
                                {"old": "'ok'", "new": "FAIL_EXECUTION"}
                            ],
                        }
                    ]
                },
                plan=plan,
            )
            session = project / ".psmatrix/session.json"
            validation_report = {
                "status": "FAIL",
                "targets": [validation_target(source, status="FAIL_EXECUTION")],
            }
            with patch(
                "psmatrix.repair.run_validation",
                return_value=(1, validation_report, "top-secret", "top-secret"),
            ) as validation_call:
                result = apply_and_validate(
                    project,
                    home,
                    bundle,
                    validation,
                    session_path=session,
                    max_attempts=1,
                )
                self.assertFalse(result["accepted"])
                serialized = session.read_text(encoding="utf-8")
                self.assertNotIn("top-secret", serialized)
                self.assertIn("<redacted>", serialized)
                with self.assertRaises(RepairError):
                    apply_and_validate(
                        project,
                        home,
                        bundle,
                        validation,
                        session_path=session,
                        max_attempts=1,
                    )
            validation_call.assert_called_once()


class GateTests(unittest.TestCase):
    def test_signed_gate_rejects_source_changed_after_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            report = {
                "tool_version": "0.8.0",
                "status": "PASS",
                "targets": [{"source": str(source), "runtime_id": RUNTIME_ID}],
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
