from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / ".github" / "workflows" / "ops-windows-lab-audit-observer.yml"


class WindowsLabAuditObserverTests(unittest.TestCase):
    def test_observer_watches_only_scheduler_and_prerequisite_sources(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")
        self.assertIn(
            "workflows: [ci-selfhosted-scheduler-diagnostic, ops-windows-lab-prereq-audit]",
            raw,
        )
        self.assertIn("types: [in_progress, completed]", raw)

    def test_machine_state_distinguishes_assignment_from_prerequisite_failure(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        for fragment in (
            "machine_status='SCHEDULER_PROVEN'",
            "machine_status='SCHEDULER_ASSIGNED'",
            "machine_status='UNRESOLVED'",
            "machine_status='PREREQUISITES_FAILED'",
            "machine_status='PREREQUISITE_RUNNING'",
            "machine_status='PREREQUISITE_QUEUED'",
            "machine_status='RECOVERED'",
            "machine_reason='prerequisite_audit_non_success'",
            "machine_reason='audit_runner_not_accepted'",
            "machine_reason='audit_terminal_without_runner_proof'",
            "machine_reason='audit_noncanonical_source'",
        ):
            self.assertIn(fragment, raw)

        prereq_failure = raw.index("machine_status='PREREQUISITES_FAILED'")
        recovered = raw.index("machine_status='RECOVERED'")
        self.assertNotEqual(prereq_failure, recovered)

    def test_prerequisite_failure_requires_runner_acceptance(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        accepted_terminal = "elif [[ \"$status\" == 'completed' && \"$runner_accepted\" == 'true' ]]; then"
        self.assertIn(accepted_terminal, raw)
        accepted_index = raw.index(accepted_terminal)
        failure_index = raw.index("machine_status='PREREQUISITES_FAILED'", accepted_index)
        unresolved_index = raw.index("machine_reason='audit_terminal_without_runner_proof'", failure_index)
        self.assertLess(accepted_index, failure_index)
        self.assertLess(failure_index, unresolved_index)

    def test_recovery_requires_canonical_main_push_audit_source(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        self.assertIn("branch=$(jq -r '.head_branch // \"\"' <<<\"$run\")", raw)
        self.assertIn(
            "if [[ \"$kind\" == 'audit' && ( \"$event\" != 'push' || \"$branch\" != 'main' ) ]]; then",
            raw,
        )
        self.assertIn("canonical_source=false", raw)
        self.assertIn("machine_canonical_source=\"$canonical_source\"", raw)
        self.assertIn("canonical_source=%s", raw)

        noncanonical = raw.index("machine_reason='audit_noncanonical_source'")
        recovered = raw.index("machine_status='RECOVERED'", noncanonical)
        self.assertLess(noncanonical, recovered)

    def test_successful_prerequisite_audit_is_the_only_recovered_state(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        self.assertEqual(raw.count("machine_status='RECOVERED'"), 1)
        recovered_block = raw.split("machine_status='RECOVERED'", 1)[1].split(
            "elif [[ \"$status\" == 'completed'", 1
        )[0]
        self.assertIn("machine_reason='prerequisite_audit_success'", recovered_block)
        self.assertIn("scheduler_proven=true", recovered_block)
        self.assertIn("prerequisites_proven=true", recovered_block)
        self.assertIn("recovery_proven=true", recovered_block)

    def test_machine_comment_is_updated_idempotently(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        self.assertIn('startswith("NAVEAX_RUNNER_STATE ")', raw)
        self.assertIn("issues/comments/$machine_comment_id", raw)
        self.assertIn("--method PATCH", raw)
        self.assertIn("machine_state_idempotent=true", raw)
        self.assertIn("canonical_source=%s", raw)
        self.assertIn("scheduler_assignment_proven=%s", raw)
        self.assertIn("prerequisites_proven=%s", raw)
        self.assertIn("recovery_proven=%s", raw)
        self.assertIn("secret_values_logged=false", raw)

    def test_observer_never_dispatches_or_reruns_recovery_workflows(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        forbidden = (
            "gh workflow run",
            "/dispatches",
            "/rerun",
            "rerun-failed-jobs",
            "cancel-in-progress: true",
        )
        for fragment in forbidden:
            self.assertNotIn(fragment, raw)

        self.assertIn("scheduler_or_audit_dispatch_created=false", raw)
        self.assertIn("audit_rerun_created=false", raw)


if __name__ == "__main__":
    unittest.main()
