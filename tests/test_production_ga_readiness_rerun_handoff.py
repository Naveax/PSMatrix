from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-ProductionGAReadinessRerunHandoff.ps1"


def summary(*, mutation: bool = True, receipt: bool = True) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-full-41check-provisioning-operation",
        "version": "2.0.0",
        "status": "PROVISIONED_AND_RECEIPT_VERIFIED" if mutation else "NO_NAME_MUTATION_REQUIRED",
        "local_check_count": 19,
        "external_or_review_check_count": 22,
        "total_material_check_count": 41,
        "fragment_count": 5,
        "present_after": 41,
        "missing_after": 0,
        "names_only_inventory_complete": True,
        "readiness_rerun_candidate": True,
        "dry_run": False,
        "github_environment_mutation_executed": mutation,
        "provisioning_receipt_verified": receipt if mutation else False,
        "selected_check_count": 41 if mutation else 0,
        "missing_before": 41 if mutation else 0,
        "production_readiness_verified": False,
        "production_evidence_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


class ProductionGAReadinessRerunHandoffTests(unittest.TestCase):
    def run_handoff(self, value: dict[str, object]) -> subprocess.CompletedProcess[str]:
        pwsh = shutil.which("pwsh")
        if not pwsh:
            self.skipTest("pwsh required")
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "full-41-operation.json"
            receipt.write_text(json.dumps(value) + "\n", encoding="utf-8")
            return subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-ProvisioningSummary",
                    str(receipt),
                    "-DryRun",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )

    def test_verified_mutation_can_reach_readiness_operator_dry_run(self) -> None:
        completed = self.run_handoff(summary())
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("production_ga_readiness_rerun_handoff=PASS", completed.stdout)
        self.assertIn("production_ga_workflow_dispatched=false", completed.stdout)
        self.assertIn("production_readiness_verified=false", completed.stdout)
        self.assertIn("ga_eligible=false", completed.stdout)

    def test_already_present_exact_41_can_handoff_without_fake_receipt(self) -> None:
        completed = self.run_handoff(summary(mutation=False, receipt=False))
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("names_only_inventory=41/41", completed.stdout)

    def test_mutation_without_verified_receipt_fails_closed(self) -> None:
        completed = self.run_handoff(summary(mutation=True, receipt=False))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("verified post-provision receipt", completed.stdout)

    def test_dry_run_provisioning_summary_cannot_authorize_readiness(self) -> None:
        value = summary()
        value["dry_run"] = True
        value["status"] = "DRY_RUN_PASS"
        completed = self.run_handoff(value)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("completed non-dry-run", completed.stdout)

    def test_source_uses_named_workflow_splatting_and_frozen_readiness_workflow(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("@workflowArgs", text)
        self.assertIn(".github/workflows/ga-final-production-readiness.yml", text)
        self.assertIn("final/2.0.0-production-control-plane-publication-anchor", text)
        self.assertNotIn("InputsJson =", text)
        self.assertIn("ga_eligible=false", text)


if __name__ == "__main__":
    unittest.main()
