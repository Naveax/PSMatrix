from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_stale_release_work_cleanup.py"


def load_module():
    spec = importlib.util.spec_from_file_location("stale_release_work_cleanup_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StaleReleaseWorkCleanupVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.closure = {
            "schema": 1,
            "kind": "psmatrix.release-closure-readiness",
            "version": "2.0.0",
            "status": "READY_FOR_RELEASE_CLOSURE",
            "execution_head": "a" * 40,
            "ga_eligible": True,
            "release_closed": False,
        }
        self.release = {
            "schema": 1,
            "kind": "psmatrix.final-immutable-release-verification",
            "version": "2.0.0",
            "status": "PASS",
            "tag": "v2.0.0",
            "final_immutable_ga_anchor_created": True,
            "release_published": True,
            "release_closed": False,
        }
        self.clean_branches = [
            {"name": "main"},
            {"name": "final/2.0.0-production-control-plane-publication-anchor"},
            {"name": "final/2.0.0-verification-hardening-publication-anchor"},
        ]

    def test_clean_release_work_set_passes(self) -> None:
        value = self.module.verify(self.closure, self.release, self.clean_branches, [])
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["stale_branch_count"], 0)
        self.assertEqual(value["stale_open_pr_count"], 0)
        self.assertTrue(value["stale_branch_pr_cleanup_completed"])
        self.assertFalse(value["release_closed"])

    def test_prod_branch_or_open_pr_blocks_cleanup(self) -> None:
        with self.assertRaises(self.module.StaleReleaseWorkCleanupError):
            self.module.verify(self.closure, self.release, self.clean_branches + [{"name": "prod/still-open"}], [])
        pulls = [{"number": 99, "state": "open", "head": {"ref": "ops/still-open"}}]
        with self.assertRaises(self.module.StaleReleaseWorkCleanupError):
            self.module.verify(self.closure, self.release, self.clean_branches, pulls)

    def test_frozen_anchor_branches_are_allowed(self) -> None:
        branches = self.clean_branches + [{"name": "final/2.0.0-ga-publication-anchor"}]
        value = self.module.verify(self.closure, self.release, branches, [])
        self.assertTrue(value["stale_branch_pr_cleanup_completed"])

    def test_final_release_branch_not_on_allowlist_is_stale(self) -> None:
        branches = self.clean_branches + [{"name": "final/2.0.0-some-old-work"}]
        with self.assertRaises(self.module.StaleReleaseWorkCleanupError):
            self.module.verify(self.closure, self.release, branches, [])

    def test_source_uses_bounded_pagination_and_never_deletes(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("per_page=100", text)
        self.assertIn("page > 100", text)
        self.assertIn("STALE_PREFIXES", text)
        self.assertIn("ALLOWED_BRANCHES", text)
        self.assertIn("stale_branch_pr_cleanup_completed", text)
        self.assertNotIn("git push --delete", text)
        self.assertNotIn("DELETE", text)


if __name__ == "__main__":
    unittest.main()
