import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.adversarial import (
    adversarial_corpus_manifest,
    list_adversarial_cases,
    run_adversarial_campaign,
    write_adversarial_evidence,
)


class AdversarialTests(unittest.TestCase):
    def test_catalog_has_unique_cases(self):
        cases = list_adversarial_cases()
        ids = [item["id"] for item in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 19)
        manifest = adversarial_corpus_manifest()
        self.assertEqual(manifest["case_count"], len(ids))
        self.assertTrue(manifest["sha256"])
        self.assertGreaterEqual(len(manifest["files"]), 6)

    def test_campaign_is_fail_closed_but_runtime_can_be_inconclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = run_adversarial_campaign(
                home=root / "home",
                runtime_version="7.6.4",
                output=root / "report.json",
            )
            self.assertTrue((root / "report.json").is_file())
            payload = json.loads((root / "report.json").read_text())
            self.assertEqual(payload["kind"], "psmatrix.adversarial-campaign")
            self.assertEqual(payload["summary"]["FAIL"], 0, payload)
            self.assertIn(payload["status"], {"PASS", "PASS_WITH_GAPS"})
            runtime = next(item for item in payload["cases"] if item["case_id"] == "runtime-secret-canary")
            self.assertEqual(runtime["status"], "INCONCLUSIVE")


    def test_evidence_is_deterministic_for_same_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = run_adversarial_campaign(
                home=root / "home",
                runtime_version="7.6.4",
                categories={"secret-handling"},
            )
            first = root / "first.zip"
            second = root / "second.zip"
            first_meta = write_adversarial_evidence(report, first)
            second_meta = write_adversarial_evidence(report, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_meta["sha256"], second_meta["sha256"])
            self.assertEqual(first_meta["corpus_sha256"], report.corpus["sha256"])

    def test_strict_mode_rejects_inconclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            report = run_adversarial_campaign(
                home=Path(temp) / "home",
                runtime_version="7.6.4",
                strict=True,
                categories={"secret-handling"},
            )
            self.assertEqual(report.status, "FAIL_INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
