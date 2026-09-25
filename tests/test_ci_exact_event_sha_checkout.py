from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CIExactEventShaCheckoutTests(unittest.TestCase):
    def test_checkout_fetches_immutable_event_sha_not_mutable_pr_ref(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("& git fetch --no-tags origin $expected", source)
        self.assertNotIn("& git fetch --no-tags origin $eventRef", source)
        self.assertIn("Exact event SHA fetch failed:", source)
        self.assertIn("Fetched event SHA $fetched does not match GITHUB_SHA $expected.", source)

    def test_event_ref_is_still_validated_but_not_used_as_checkout_identity(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("$eventRef = [string]$env:GITHUB_REF", source)
        self.assertIn("Unsupported CI event ref:", source)
        fetch = source.index("& git fetch --no-tags origin $expected")
        checkout = source.index("& git checkout --detach --force $expected")
        self.assertLess(fetch, checkout)


if __name__ == "__main__":
    unittest.main()
