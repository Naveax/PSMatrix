from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "ga" / "Invoke-ProductionGAEnvironmentProvisioning.ps1"
FULL41 = ROOT / "scripts" / "ga" / "Invoke-ProductionGAFullFortyOneCheckProvisioning.ps1"
AUDIT = ROOT / "scripts" / "ga" / "audit_production_ga_environment_inventory.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


def _load_audit():
    spec = importlib.util.spec_from_file_location("production_ga_inventory_boundary", AUDIT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Production GA inventory module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGACommandBoundaryRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = _load_audit()
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.pwsh = shutil.which("pwsh")

    def _inventory(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-environment-name-inventory",
            "version": "2.0.0",
            "environments": {
                row["name"]: {"secrets": [], "vars": []}
                for row in self.contract["environments"]
            },
        }

    def test_inventory_requires_exact_environment_set(self) -> None:
        inventory = self._inventory()
        inventory["environments"].pop("production-ga-root-signing")
        with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "exact Production GA environment set"):
            self.audit.audit_inventory(self.contract, inventory)
        inventory = self._inventory()
        inventory["environments"]["attacker-extra"] = {"secrets": [], "vars": []}
        with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "exact Production GA environment set"):
            self.audit.audit_inventory(self.contract, inventory)

    def test_inventory_rejects_duplicate_and_non_string_names(self) -> None:
        inventory = self._inventory()
        inventory["environments"]["production-ga-release-signing"]["secrets"] = ["X", "X"]
        with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "duplicate name"):
            self.audit.audit_inventory(self.contract, inventory)
        inventory = self._inventory()
        inventory["environments"]["production-ga-release-signing"]["secrets"] = [123]
        with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "invalid name"):
            self.audit.audit_inventory(self.contract, inventory)

    def test_live_inventory_rejects_duplicate_names_and_unknown_kind(self) -> None:
        with mock.patch.object(
            self.audit.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout='[{"name":"X"},{"name":"X"}]', stderr=""),
        ):
            with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "duplicate name entry"):
                self.audit._gh_names("gh", "Naveax/PSMatrix", "production-ga-release-signing", "secret")
        with mock.patch.object(self.audit.subprocess, "run") as run:
            with self.assertRaisesRegex(self.audit.EnvironmentInventoryError, "unsupported GitHub environment inventory kind"):
                self.audit._gh_names("gh", "Naveax/PSMatrix", "production-ga-release-signing", "token")
        run.assert_not_called()

    def test_helper_source_freezes_final_mutation_boundary(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        for required in (
            "Trusted gh executable must stay outside the repository",
            "Production provisioning material map contains an undeclared environment identity",
            "material source path must be a string",
            "Assert-ExternalMaterialFile $Source $repoRoot $Label",
            "Protect-TemporaryPath $stageRoot $true",
            "command output was intentionally redacted",
            "Remove-Item -LiteralPath $staged -Force",
            "'--repo',$ExpectedRepository",
        ):
            self.assertIn(required, source)
        self.assertNotIn("$stagedPlan", source)
        self.assertNotIn("Get-Content -Raw -LiteralPath $stderr", source)

    def test_full41_source_requires_live_inventory_for_mutation(self) -> None:
        source = FULL41.read_text(encoding="utf-8")
        for required in (
            "OfflineInventoryBefore is permitted only with DryRun",
            "mutating operations require a live GitHub inventory",
            "Assert-NoLinkOrReparsePath $offlineInventory 'Offline inventory'",
            "Trusted gh executable must stay outside the repository",
            "readiness_rerun_candidate=((-not $DryRun.IsPresent) -and ($presentAfter -eq 41))",
        ):
            self.assertIn(required, source)

    def test_offline_inventory_is_rejected_before_mutating_workspace_creation(self) -> None:
        if self.pwsh is None:
            self.skipTest("pwsh required")
        with tempfile.TemporaryDirectory(prefix="psmatrix-full41-offline-guard-") as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps(self._inventory()), encoding="utf-8")
            completed = subprocess.run(
                [
                    self.pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(FULL41),
                    "-Root",
                    str(workspace),
                    "-PublicAuthMaterialRoot",
                    str(root / "missing-public-auth"),
                    "-OtlpEndpointFile",
                    str(root / "missing-endpoint"),
                    "-OtlpHeadersFile",
                    str(root / "missing-headers"),
                    "-SecurityReviewPacket",
                    str(root / "missing-packet"),
                    "-SecurityReviewReport",
                    str(root / "missing-report"),
                    "-OfflineInventoryBefore",
                    str(inventory),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("permitted only with DryRun", completed.stdout)
            self.assertFalse(workspace.exists())

    def test_helper_rejects_undeclared_mapped_environment_in_dry_run(self) -> None:
        if self.pwsh is None:
            self.skipTest("pwsh required")
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-boundary-") as temporary:
            root = Path(temporary)
            secret = root / "secret.txt"
            secret.write_text("fixture\n", encoding="utf-8")
            material_map = root / "map.json"
            material_map.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "psmatrix.production-ga-environment-material-map",
                        "version": "2.0.0",
                        "environments": {
                            "production-ga-release-signing": {
                                "secrets": {"PSMATRIX_RELEASE_PRIVATE_KEY": str(secret)},
                                "vars": {},
                            },
                            "attacker-extra": {"secrets": {}, "vars": {}},
                        },
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    self.pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(HELPER),
                    "-MaterialMap",
                    str(material_map),
                    "-Contract",
                    str(CONTRACT),
                    "-Environment",
                    "production-ga-release-signing",
                    "-DryRun",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("undeclared environment identity", completed.stdout)


if __name__ == "__main__":
    unittest.main()
