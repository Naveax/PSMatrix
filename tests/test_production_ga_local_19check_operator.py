from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-ProductionGALocalNineteenCheckProvisioning.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


class ProductionGALocalNineteenCheckOperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 required")

    def _empty_inventory(self) -> dict:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-environment-name-inventory",
            "version": "2.0.0",
            "environments": {row["name"]: {"secrets": [], "vars": []} for row in contract["environments"]},
        }

    def test_dry_run_prepares_and_selects_exact_local_nineteen_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-19-operator-") as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps(self._empty_inventory()), encoding="utf-8")
            completed = subprocess.run(
                [
                    str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT),
                    "-Root", str(workspace), "-DryRun", "-OfflineInventoryBefore", str(inventory),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("production_ga_local_19check_operation=DRY_RUN_PASS", completed.stdout)
            self.assertIn("selected_checks=19", completed.stdout)
            self.assertIn("github_environment_mutation_executed=false", completed.stdout)
            summary = json.loads((workspace / "local-19-provisioning-operation.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(summary["locally_prepared_check_count"], 19)
            self.assertEqual(summary["external_or_review_check_count"], 22)
            self.assertEqual(summary["local_missing_before"], 19)
            self.assertEqual(summary["selected_check_count"], 19)
            self.assertFalse(summary["github_environment_mutation_executed"])
            self.assertFalse(summary["provisioning_receipt_verified"])
            self.assertFalse(summary["production_readiness_verified"])
            self.assertFalse(summary["ga_eligible"])
            self.assertTrue(Path(summary["artifacts"]["local_material_map"]).is_file())
            selected = json.loads(Path(summary["artifacts"]["selected_material_map"]).read_text(encoding="utf-8"))
            self.assertEqual(selected["check_count"], 19)

    def test_repo_local_workspace_is_rejected_before_material_generation(self) -> None:
        forbidden = ROOT / ".tmp-local-19-operator"
        try:
            completed = subprocess.run(
                [str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT), "-Root", str(forbidden), "-DryRun"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("must stay outside the repository", completed.stdout)
            self.assertFalse(forbidden.exists())
        finally:
            if forbidden.exists():
                shutil.rmtree(forbidden)


if __name__ == "__main__":
    unittest.main()
