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
        self.assertIn("for ($attempt = 1; $attempt -le 3; $attempt++)", source)
        self.assertIn("Frozen branch-object fetch attempt $attempt failed", source)
        self.assertIn("Exact event SHA fetch attempt $attempt failed", source)
        self.assertIn("Start-Sleep -Seconds (2 * $attempt)", source)
        self.assertIn("GIT_HTTP_LOW_SPEED_LIMIT", source)
        self.assertIn("GIT_HTTP_LOW_SPEED_TIME", source)
        self.assertIn("Fetched event SHA $fetched does not match GITHUB_SHA $expected.", source)

    def test_event_ref_is_still_validated_but_not_used_as_checkout_identity(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("$eventRef = [string]$env:GITHUB_REF", source)
        self.assertIn("Unsupported CI event ref:", source)
        fetch = source.index("& git fetch --no-tags origin $expected")
        checkout = source.index("& git checkout --detach --force $expected")
        self.assertLess(fetch, checkout)


    def test_frozen_finalv2_guard_isolated_base_and_protected_head(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        frozen = (ROOT / "tests" / "test_final_v2_release_control_migration.py").read_text(encoding="utf-8")
        self.assertIn("self.assertEqual(changed, allowed)", frozen)
        self.assertIn("self.assertEqual(len(changed), 55)", frozen)
        self.assertIn("github.event.pull_request.base.sha", source)
        self.assertIn("git merge-base --is-ancestor $baseSha HEAD", source)
        self.assertIn("git diff --no-renames --name-only $baseSha HEAD --", source)
        self.assertIn("$protected -ccontains $_", source)
        self.assertIn("$protectedChanges.Count -eq 0", source)
        self.assertIn("& git worktree add --detach -- $frozenRoot $baseSha", source)
        self.assertIn("& python -m unittest $module -v", source)
        self.assertIn("& git worktree remove --force -- $frozenRoot", source)
        self.assertIn("throw 'Frozen Final-V2 historical test failed.'", source)
        self.assertIn("frozen_finalv2=HEAD protected_changed=", source)


if __name__ == "__main__":
    unittest.main()
