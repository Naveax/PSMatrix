from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ops-windows-lab-prereq-audit.yml"


class WindowsLabPrerequisiteWorkflowTests(unittest.TestCase):
    def test_prerequisite_audit_is_fail_closed_and_value_free(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")

        required_fragments = (
            "ga_root_absolute = $rootAbsolute",
            "failed_required_checks = $failed",
            "audit_pass = $auditPass",
            "Publish value-free audit to issue 261",
            "Enforce required Windows lab prerequisites",
            "windows_lab_prereq_audit=PASS fail_closed=true",
            "external_iso_count_gate=false",
            "No secret values, hashes, lengths, or configured paths were emitted.",
        )
        for fragment in required_fragments:
            self.assertIn(fragment, raw)

        required_checks = (
            "runner_exact_naveax",
            "ga_root_configured",
            "ga_root_absolute",
            "ga_root_exists",
            "ga_config_dir_exists",
            "media_external_dir_exists",
            "hyperv_cmd_available",
            "vmms_running",
            "wps40_admin_secret_present",
            "wps50_admin_secret_present",
            "wps51_admin_secret_present",
        )
        for check in required_checks:
            self.assertIn(f"Name = '{check}'", raw)

        self.assertLess(
            raw.index("- name: Publish value-free audit to issue 261"),
            raw.index("- name: Enforce required Windows lab prerequisites"),
        )
        self.assertIn("if (-not [bool]$v.audit_pass -or $failed.Count -ne 0)", raw)
        self.assertIn('throw "Windows-lab prerequisite audit failed required checks: $failedText"', raw)

    def test_iso_count_is_not_an_early_prerequisite_gate(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("external_iso_count = $isoCount", raw)
        self.assertIn("external_iso_count_gate = $false", raw)
        self.assertNotIn("Name = 'external_iso_count'", raw)
        self.assertIn(
            "canonical RC4 media completeness is enforced later by the reviewed media inventory/selection workflow",
            raw,
        )

    def test_issue_comment_interpolates_and_updates_idempotently(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")
        publish = raw.split("- name: Publish value-free audit to issue 261", 1)[1].split(
            "- name: Enforce required Windows lab prerequisites", 1
        )[0]

        self.assertNotIn("`$env:", publish)
        self.assertNotIn("`$(", publish)
        self.assertIn("Run: $env:GITHUB_RUN_ID", publish)
        self.assertIn("Gate status: $gateStatus", publish)
        self.assertIn("Runner exact NAVEAX/Windows: $($v.runner_exact_naveax)", publish)
        self.assertIn('startswith("### Windows-lab prerequisite audit")', publish)
        self.assertIn("--method PATCH", publish)
        self.assertIn("audit_comment_idempotent=true", publish)


    def test_provisioning_dispatch_is_exact_head_bound_and_manual_dispatch_stays_diagnostic(self) -> None:
        raw = WORKFLOW.read_text(encoding="utf-8")

        for fragment in (
            "repository_dispatch:",
            "types: [windows_lab_prereq_audit]",
            "RECOVERY_DISPATCH_SCHEMA:",
            "RECOVERY_DISPATCH_SOURCE:",
            "RECOVERY_DISPATCH_EXPECTED_HEAD:",
            "$env:RECOVERY_DISPATCH_SCHEMA -cne '1'",
            "$env:RECOVERY_DISPATCH_SOURCE -cne 'windows-lab-operational-provisioning'",
            "$env:RECOVERY_DISPATCH_EXPECTED_HEAD -cne $env:GITHUB_SHA",
            "event=repository_dispatch exact_head_bound=true",
            "event=workflow_dispatch diagnostic_only=true",
        ):
            self.assertIn(fragment, raw)

        trigger_guard = raw.index("- name: Verify canonical recovery trigger provenance")
        prerequisite_read = raw.index("- name: Audit value-free Windows lab prerequisites")
        self.assertLess(trigger_guard, prerequisite_read)


if __name__ == "__main__":
    unittest.main()
