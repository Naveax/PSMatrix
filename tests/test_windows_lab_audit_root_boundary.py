from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ops-windows-lab-prereq-audit.yml"


class WindowsLabAuditRootBoundaryTests(unittest.TestCase):
    def test_audit_rechecks_runner_arch_and_root_isolation_independently(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")

        for fragment in (
            "$runnerArchX64 = ($env:RUNNER_ARCH -eq 'X64')",
            "Name = 'runner_arch_x64'",
            "Name = 'ga_root_repository_disjoint'",
            "Name = 'ga_root_no_reparse_points'",
            "Name = 'ga_layout_no_reparse_points'",
            "$rootRepositoryDisjoint = -not (Test-PathWithinRoot -Candidate $root -Root $workspace) -and -not (Test-PathWithinRoot -Candidate $workspace -Root $root)",
            "$rootNoReparsePoints = Test-NoLinkOrReparsePath -Path $root",
            "$layoutNoReparsePoints = (Test-NoLinkOrReparsePath -Path $external) -and (Test-NoLinkOrReparsePath -Path $config)",
        ):
            self.assertIn(fragment, raw)

    def test_reparse_and_overlap_checks_are_fail_closed(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("$rootRepositoryDisjoint = $false", raw)
        self.assertIn("$rootNoReparsePoints = $false", raw)
        self.assertIn("$layoutNoReparsePoints = $false", raw)
        self.assertIn("return $false", raw)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", raw)
        self.assertIn("$current.PSObject.Properties['LinkType']", raw)

    def test_issue_output_remains_value_free(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")
        publish = raw.split("- name: Publish value-free audit to issue 261", 1)[1].split(
            "- name: Enforce required Windows lab prerequisites", 1
        )[0]

        for fragment in (
            "Runner architecture X64: $($v.runner_arch_x64)",
            "GA root/repository disjoint: $($v.ga_root_repository_disjoint)",
            "GA root has no links/reparse points: $($v.ga_root_no_reparse_points)",
            "GA layout has no links/reparse points: $($v.ga_layout_no_reparse_points)",
            "No secret values, hashes, lengths, or configured paths were emitted.",
        ):
            self.assertIn(fragment, publish)

        self.assertNotIn("PSMATRIX_WINDOWS_GA_ROOT: $env:PSMATRIX_WINDOWS_GA_ROOT", publish)
        self.assertNotIn("GA root path:", publish)


if __name__ == "__main__":
    unittest.main()
