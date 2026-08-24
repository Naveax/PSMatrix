from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "audit_production_ga_environment_inventory.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("production_ga_environment_inventory", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Production GA environment inventory module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGAEnvironmentInventoryAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _inventory(self, *, complete: bool) -> dict:
        environments = {}
        for row in self.contract["environments"]:
            environments[row["name"]] = {
                "secrets": list(row["required_secrets"]) if complete else [],
                "vars": list(row["required_vars"]) if complete else [],
            }
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-environment-name-inventory",
            "version": "2.0.0",
            "environments": environments,
        }

    def test_empty_inventory_is_exact_zero_of_forty_one(self) -> None:
        value = self.module.audit_inventory(self.contract, self._inventory(complete=False))
        self.assertEqual(value["status"], "INCOMPLETE")
        self.assertEqual(value["environment_count"], 12)
        self.assertEqual(value["required_check_count"], 41)
        self.assertEqual(value["present_check_count"], 0)
        self.assertEqual(value["missing_check_count"], 41)
        self.assertFalse(value["values_observed"])
        self.assertFalse(value["secret_hashes_observed"])
        self.assertFalse(value["secret_lengths_observed"])

    def test_exact_complete_inventory_is_forty_one_of_forty_one_pass(self) -> None:
        value = self.module.audit_inventory(self.contract, self._inventory(complete=True))
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["present_check_count"], 41)
        self.assertEqual(value["missing_check_count"], 0)
        self.assertTrue(all(row["status"] == "PASS" for row in value["environments"]))

    def test_partial_environment_counts_only_declared_requirements(self) -> None:
        inventory = self._inventory(complete=False)
        release = next(row for row in self.contract["environments"] if row["name"] == "production-ga-release-signing")
        full_matrix = next(row for row in self.contract["environments"] if row["name"] == "production-ga-full-matrix")
        inventory["environments"][release["name"]]["secrets"] = list(release["required_secrets"])
        inventory["environments"][full_matrix["name"]]["vars"] = list(full_matrix["required_vars"])
        inventory["environments"][release["name"]]["secrets"].append("UNDECLARED_EXTRA_SECRET")
        value = self.module.audit_inventory(self.contract, inventory)
        self.assertEqual(value["present_check_count"], 3)
        self.assertEqual(value["missing_check_count"], 38)
        release_row = next(row for row in value["environments"] if row["environment"] == release["name"])
        self.assertEqual(release_row["extra_secrets"], ["UNDECLARED_EXTRA_SECRET"])
        self.assertEqual(release_row["present"], 1)

    def test_live_collection_requests_name_field_only_for_secrets_and_variables(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, **kwargs):
            calls.append(list(command))
            return mock.Mock(returncode=0, stdout='[{"name":"EXAMPLE"}]', stderr="")

        with mock.patch.object(self.module.subprocess, "run", side_effect=fake_run):
            names_secret = self.module._gh_names("gh", "Naveax/PSMatrix", "production-ga-release-signing", "secret")
            names_var = self.module._gh_names("gh", "Naveax/PSMatrix", "production-ga-full-matrix", "variable")
        self.assertEqual(names_secret, {"EXAMPLE"})
        self.assertEqual(names_var, {"EXAMPLE"})
        self.assertEqual(len(calls), 2)
        for command in calls:
            self.assertIn("--json", command)
            index = command.index("--json")
            self.assertEqual(command[index + 1], "name")
            self.assertEqual(command[command.index("--repo") + 1], "Naveax/PSMatrix")
            joined = " ".join(command).lower()
            self.assertNotIn("value", joined)
            self.assertNotIn("body", joined)

    def test_wrong_repository_is_rejected_before_subprocess(self) -> None:
        with mock.patch.object(self.module.subprocess, "run") as run:
            with self.assertRaisesRegex(self.module.EnvironmentInventoryError, "repository must be exactly Naveax/PSMatrix"):
                self.module.collect_inventory(self.contract, repository="attacker/example", gh="gh")
        run.assert_not_called()

    def test_gh_failure_redacts_stderr_content(self) -> None:
        sentinel = "DO-NOT-REFLECT-THIS-CONTENT"
        with mock.patch.object(
            self.module.subprocess,
            "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr=sentinel),
        ):
            with self.assertRaises(self.module.EnvironmentInventoryError) as raised:
                self.module._gh_names("gh", "Naveax/PSMatrix", "production-ga-release-signing", "secret")
        message = str(raised.exception)
        self.assertIn("intentionally redacted", message)
        self.assertNotIn(sentinel, message)

    def test_strict_json_rejects_duplicate_object_keys_and_nonfinite_constants(self) -> None:
        with self.assertRaisesRegex(self.module.EnvironmentInventoryError, "duplicate object key"):
            self.module._strict_json_loads('{"name":"A","name":"B"}')
        with self.assertRaisesRegex(self.module.EnvironmentInventoryError, "non-standard numeric constant"):
            self.module._strict_json_loads('{"value":NaN}')

    def test_offline_inventory_roundtrip_never_requires_secret_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-inventory-") as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(self._inventory(complete=True)), encoding="utf-8")
            loaded = self.module._strict_json_loads(path.read_text(encoding="utf-8"))
            value = self.module.audit_inventory(self.contract, loaded)
            self.assertEqual(value["status"], "PASS")
            self.assertFalse(value["values_observed"])
            self.assertFalse(value["secret_hashes_observed"])
            self.assertFalse(value["secret_lengths_observed"])
            for row in value["environments"]:
                self.assertEqual(
                    set(row),
                    {
                        "environment",
                        "status",
                        "required",
                        "present",
                        "missing_secrets",
                        "missing_vars",
                        "extra_secrets",
                        "extra_vars",
                    },
                )

    def test_source_pins_repository_and_redacts_command_errors(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_REPOSITORY = "Naveax/PSMatrix"', source)
        self.assertIn("_resolve_trusted_gh", source)
        self.assertIn("command output was intentionally redacted", source)
        self.assertIn("object_pairs_hook=_reject_duplicate_pairs", source)
        self.assertNotIn("completed.stderr.strip()", source)


if __name__ == "__main__":
    unittest.main()
