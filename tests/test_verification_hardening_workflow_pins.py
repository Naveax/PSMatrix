from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "verification-hardening-source-certification.yml"
SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$")


class VerificationHardeningWorkflowPinTests(unittest.TestCase):
    def test_all_actions_are_immutable_sha_pinned(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = [
            line.strip().removeprefix("uses: ")
            for line in text.splitlines()
            if line.strip().startswith("uses: ")
        ]
        self.assertEqual(len(uses), 2)
        for value in uses:
            with self.subTest(value=value):
                self.assertRegex(value, SHA_PIN)
        self.assertIn("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", text)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", text)

    def test_checkout_retains_publication_ancestry_without_credentials(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target:", text)


if __name__ == "__main__":
    unittest.main()
