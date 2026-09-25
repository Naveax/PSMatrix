from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CIWorkspaceCleanupContractTests(unittest.TestCase):
    def test_checkout_and_frozen_restore_use_bounded_idempotent_cleanup(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        helper = "function Clear-WorkspaceContents([string]$Path)"
        self.assertEqual(source.count(helper), 2)
        self.assertGreaterEqual(source.count("catch [System.Management.Automation.ItemNotFoundException]"), 2)
        self.assertGreaterEqual(source.count("for ($attempt = 1; $attempt -le 3; $attempt++)"), 2)
        self.assertGreaterEqual(source.count("Workspace cleanup did not converge; remaining entries:"), 2)
        self.assertNotIn(
            "Get-ChildItem -LiteralPath $workspace -Force | Remove-Item -Recurse -Force -ErrorAction Stop",
            source,
        )

    def test_cleanup_is_verified_before_checkout_and_archive_restore(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        checkout_call = "Clear-WorkspaceContents $env:GITHUB_WORKSPACE"
        restore_call = "Clear-WorkspaceContents $workspace"
        self.assertEqual(source.count(checkout_call), 1)
        self.assertEqual(source.count(restore_call), 1)
        self.assertLess(source.index(checkout_call), source.index("& git init ."))
        self.assertLess(source.index(restore_call), source.index("Expand-Archive -LiteralPath $archive"))
        self.assertIn("if ($remaining.Count -ne 0)", source)


if __name__ == "__main__":
    unittest.main()
