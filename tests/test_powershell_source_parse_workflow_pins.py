from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
PINNED_CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$")


class PowerShellSourceParseWorkflowPinTests(unittest.TestCase):
    def test_checkout_is_current_immutable_v4_pin(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = [
            line.strip().removeprefix("uses: ")
            for line in text.splitlines()
            if line.strip().startswith("uses: ")
        ]
        self.assertEqual(len(uses), 1)
        self.assertRegex(uses[0], SHA_PIN)
        self.assertIn(PINNED_CHECKOUT, text)

    def test_parse_job_has_read_only_checkout_boundary(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("persist-credentials: false", text)
        self.assertIn("fetch-depth: 1", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target:", text)


if __name__ == "__main__":
    unittest.main()
