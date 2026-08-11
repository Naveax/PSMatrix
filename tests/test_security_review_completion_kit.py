from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "security_review_completion_kit.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("security_review_completion_kit", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load security review completion kit")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityReviewCompletionKitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _packet(self, root: Path) -> tuple[Path, dict]:
        commit = "c" * 40
        source_sha = "a" * 64
        release_sha = "b" * 64
        manifest = {
            "schema": 1,
            "kind": "psmatrix.security-review-packet",
            "version": "2.0.0",
            "reviewed_commit": commit,
            "source_archive": {"name": "psmatrix-2.0.0-source.zip", "sha256": source_sha, "size": 123},
            "release_manifest": {"name": "psmatrix-2.0.0-release.json", "sha256": release_sha, "size": 456},
            "required_sections": list(self.module._EXPECTED_SECTIONS),
            "required_methodologies": list(self.module._EXPECTED_METHODS),
        }
        template = {
            "schema": 1,
            "kind": "psmatrix.independent-security-review",
            "status": "DRAFT",
            "observed_at": "REPLACE_WITH_ISO_8601_UTC",
            "reviewed_commit": commit,
            "reviewed_release_sha256": release_sha,
            "reviewed_source_sha256": source_sha,
            "review_hours": 0,
            "reviewer": {
                "name": "REPLACE",
                "organization": "REPLACE",
                "role": "REPLACE",
                "contact": "REPLACE",
                "conflict_of_interest": None,
                "key_controlled_by_reviewer": None,
            },
            "methodologies": list(self.module._EXPECTED_METHODS),
            "sections": {
                name: {"status": "NOT_REVIEWED", "summary": "", "evidence": [], "findings": []}
                for name in self.module._EXPECTED_SECTIONS
            },
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "limitations": [],
            "reviewer_declaration": "",
        }
        packet = root / "review-packet.zip"
        with zipfile.ZipFile(packet, "w") as archive:
            archive.writestr(self.module._MANIFEST, json.dumps(manifest))
            archive.writestr(self.module._TEMPLATE, json.dumps(template))
        return packet, template

    def _completed_report(self, template: dict) -> dict:
        report = copy.deepcopy(template)
        report["status"] = "PASS"
        report["observed_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        report["review_hours"] = 12.5
        report["reviewer"] = {
            "name": "Independent Reviewer",
            "organization": "Independent Security Lab",
            "role": "Senior Security Reviewer",
            "contact": "reviewer@example.test",
            "conflict_of_interest": False,
            "key_controlled_by_reviewer": True,
        }
        for name in self.module._EXPECTED_SECTIONS:
            report["sections"][name]["status"] = "REVIEWED"
            report["sections"][name]["summary"] = f"Reviewed {name} controls and evidence."
        report["findings"] = []
        report["summary"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        report["reviewer_declaration"] = "I independently reviewed the supplied PSMatrix release evidence and control surface."
        return report

    def test_prepare_workspace_remains_draft_and_requires_independent_reviewer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-kit-") as temporary:
            root = Path(temporary)
            packet, _ = self._packet(root)
            workspace = root / "workspace"
            checklist = self.module.prepare_workspace(packet, workspace)
            report = json.loads((workspace / "security-review-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "DRAFT")
            self.assertEqual(checklist["required_sections"], list(self.module._EXPECTED_SECTIONS))
            self.assertEqual(checklist["required_methodologies"], list(self.module._EXPECTED_METHODS))
            self.assertFalse(checklist["pass_boundary"]["release_owner_may_complete_review"])
            self.assertFalse(checklist["pass_boundary"]["release_owner_may_control_reviewer_private_key"])

    def test_valid_completed_independent_report_is_ready_for_environment_variable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-kit-") as temporary:
            root = Path(temporary)
            packet, template = self._packet(root)
            report_path = root / "completed-report.json"
            report_path.write_text(json.dumps(self._completed_report(template)), encoding="utf-8")
            value = self.module.validate_completed_report(packet, report_path)
            self.assertEqual(value["status"], "PASS")
            self.assertTrue(value["independent_review"])
            self.assertTrue(value["ready_for_environment_variable"])
            self.assertEqual(value["findings"]["critical"], 0)
            self.assertEqual(value["findings"]["high"], 0)
            self.assertFalse(value["report_value_serialized"])
            self.assertFalse(value["reviewer_private_key_read"])

    def test_critical_or_high_finding_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-kit-") as temporary:
            root = Path(temporary)
            packet, template = self._packet(root)
            report = self._completed_report(template)
            report["findings"] = [{"id": "SR-001", "severity": "critical", "title": "Blocking finding", "disposition": "Open"}]
            report["summary"]["critical"] = 1
            report_path = root / "blocked-report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(self.module.SecurityReviewCompletionError):
                self.module.validate_completed_report(packet, report_path)

    def test_conflict_of_interest_or_owner_controlled_reviewer_key_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-kit-") as temporary:
            root = Path(temporary)
            packet, template = self._packet(root)
            report = self._completed_report(template)
            report["reviewer"]["conflict_of_interest"] = True
            report_path = root / "conflicted-report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(self.module.SecurityReviewCompletionError):
                self.module.validate_completed_report(packet, report_path)
            report = self._completed_report(template)
            report["reviewer"]["key_controlled_by_reviewer"] = False
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(self.module.SecurityReviewCompletionError):
                self.module.validate_completed_report(packet, report_path)


if __name__ == "__main__":
    unittest.main()
