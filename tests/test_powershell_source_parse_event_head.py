from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"


class PowerShellSourceParseEventHeadTests(unittest.TestCase):
    def test_event_head_is_verified_before_parse(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        verify = text.index("- name: Verify exact workflow event revision")
        actual = text.index('actual="$(git rev-parse HEAD)"', verify)
        compare = text.index('[[ "$actual" != "$GITHUB_SHA" ]]', actual)
        proof = text.index('echo "workflow_event_head_verified=true"', compare)
        parse = text.index("- name: Parse every tracked PowerShell script")
        self.assertLess(verify, actual)
        self.assertLess(actual, compare)
        self.assertLess(compare, proof)
        self.assertLess(proof, parse)
        self.assertIn("set -euo pipefail", text)


if __name__ == "__main__":
    unittest.main()
