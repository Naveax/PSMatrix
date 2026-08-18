from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_security_review_material_map_fragment.py"


def load():
    spec = importlib.util.spec_from_file_location("security_review_fragment", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityReviewMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()
        cls.kit = cls.module._load_kit()

    def _packet_and_report(self, root: Path) -> tuple[Path, Path, dict]:
        commit = "c" * 40
        source_sha = "a" * 64
        release_sha = "b" * 64
        manifest = {
            "schema": 1,
            "kind": "psmatrix.security-review-packet",
            "version": "2.0.0",
            "reviewed_commit": commit,
            "source_archive": {"name": "source.zip", "sha256": source_sha, "size": 123},
            "release_manifest": {"name": "release.json", "sha256": release_sha, "size": 456},
            "required_sections": list(self.kit._EXPECTED_SECTIONS),
            "required_methodologies": list(self.kit._EXPECTED_METHODS),
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
            "methodologies": list(self.kit._EXPECTED_METHODS),
            "sections": {
                name: {"status": "NOT_REVIEWED", "summary": "", "evidence": [], "findings": []}
                for name in self.kit._EXPECTED_SECTIONS
            },
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "limitations": [],
            "reviewer_declaration": "",
        }
        packet = root / "packet.zip"
        with zipfile.ZipFile(packet, "w") as archive:
            archive.writestr(self.kit._MANIFEST, json.dumps(manifest))
            archive.writestr(self.kit._TEMPLATE, json.dumps(template))
        report = copy.deepcopy(template)
        report["status"] = "PASS"
        report["observed_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        report["review_hours"] = 10.0
        report["reviewer"] = {
            "name": "Independent Reviewer",
            "organization": "Independent Lab",
            "role": "Senior Reviewer",
            "contact": "reviewer@example.test",
            "conflict_of_interest": False,
            "key_controlled_by_reviewer": True,
        }
        for name in self.kit._EXPECTED_SECTIONS:
            report["sections"][name]["status"] = "REVIEWED"
            report["sections"][name]["summary"] = f"Reviewed {name}."
        report["reviewer_declaration"] = "I independently reviewed the supplied release evidence and controls."
        report_path = root / "completed-report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return packet, report_path, report

    def test_valid_independent_report_maps_exact_one_environment_variable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-fragment-") as temporary:
            root = Path(temporary)
            packet, report, _ = self._packet_and_report(root)
            value = self.module.build_fragment(packet, report)
            self.assertEqual(value["check_count"], 1)
            entry = value["environments"]["production-ga-security-review-signing"]
            self.assertEqual(entry["secrets"], {})
            self.assertEqual(set(entry["vars"]), {"PSMATRIX_GA_SECURITY_REVIEW_REPORT_JSON"})
            self.assertTrue(Path(entry["vars"]["PSMATRIX_GA_SECURITY_REVIEW_REPORT_JSON"]).samefile(report))
            self.assertTrue(value["review"]["independent_review"])
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("Independent Reviewer", serialized)
            self.assertNotIn("reviewer@example.test", serialized)

    def test_blocking_finding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-fragment-") as temporary:
            root = Path(temporary)
            packet, report_path, report = self._packet_and_report(root)
            report["findings"] = [{"id": "SR-1", "severity": "high", "title": "block", "disposition": "Open"}]
            report["summary"]["high"] = 1
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(self.module.SecurityReviewFragmentError):
                self.module.build_fragment(packet, report_path)

    def test_repo_local_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-fragment-") as temporary:
            root = Path(temporary)
            packet, report, _ = self._packet_and_report(root)
            inside = ROOT / ".tmp-review-report.json"
            try:
                inside.write_bytes(report.read_bytes())
                with self.assertRaises(self.module.SecurityReviewFragmentError):
                    self.module.build_fragment(packet, inside)
            finally:
                inside.unlink(missing_ok=True)

    def test_hardlinked_packet_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-packet-hardlink-") as temporary:
            root = Path(temporary)
            packet, report, _ = self._packet_and_report(root)
            alias = root / "packet-alias.zip"
            try:
                os.link(packet, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.SecurityReviewFragmentError, "must not be hardlinked"):
                self.module.build_fragment(packet, report)

    def test_hardlinked_report_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-report-hardlink-") as temporary:
            root = Path(temporary)
            packet, report, _ = self._packet_and_report(root)
            alias = root / "report-alias.json"
            try:
                os.link(report, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.SecurityReviewFragmentError, "must not be hardlinked"):
                self.module.build_fragment(packet, report)

    def test_hardlinked_output_map_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-map-hardlink-") as temporary:
            root = Path(temporary)
            packet, report, _ = self._packet_and_report(root)
            value = self.module.build_fragment(packet, report)
            target = root / "target-map.json"
            output = root / "map.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.SecurityReviewFragmentError, "must not be hardlinked"):
                self.module.write_fragment(output, value)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_uses_lstat_hardlink_checks_and_atomic_output(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(output, value)", source)


if __name__ == "__main__":
    unittest.main()
