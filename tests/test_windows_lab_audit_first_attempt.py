from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / ".github" / "workflows" / "ops-windows-lab-audit-observer.yml"


class WindowsLabAuditFirstAttemptTests(unittest.TestCase):
    def test_canonical_recovery_requires_first_workflow_attempt(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        self.assertIn("attempt=$(jq -r '.run_attempt // 0' <<<\"$run\")", raw)
        self.assertIn(
            "if [[ \"$kind\" == 'audit' && ( \"$event\" != 'push' || \"$branch\" != 'main' || \"$attempt\" != '1' ) ]]; then",
            raw,
        )
        self.assertIn(
            "elif [[ \"$kind\" == 'scheduler' && ( \"$event\" != 'workflow_dispatch' || \"$attempt\" != '1' ) ]]; then",
            raw,
        )
        self.assertIn("Only a first-attempt canonical source may prove recovery", raw)

    def test_attempt_is_exposed_in_human_and_machine_state(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        self.assertIn("machine_run_attempt='none'", raw)
        self.assertIn('machine_run_attempt="$attempt"', raw)
        self.assertIn("Attempt: `%s`", raw)
        self.assertIn("run_attempt=%s", raw)

    def test_rerun_guard_precedes_recovered_state(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        attempt_guard = raw.index("\"$attempt\" != '1'")
        noncanonical = raw.index("machine_reason='audit_noncanonical_source'")
        recovered = raw.index("machine_status='RECOVERED'", noncanonical)
        self.assertLess(attempt_guard, noncanonical)
        self.assertLess(noncanonical, recovered)

    def test_observer_still_never_dispatches_or_reruns(self) -> None:
        raw = OBSERVER.read_text(encoding="utf-8")

        for forbidden in ("gh workflow run", "/rerun", "rerun-failed-jobs"):
            self.assertNotIn(forbidden, raw)
        self.assertIn("audit_rerun_created=false", raw)


if __name__ == "__main__":
    unittest.main()
