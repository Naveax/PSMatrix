from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "select_missing_production_ga_material.py"
spec = importlib.util.spec_from_file_location("selector", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def audit(missing_secret: list[str], missing_var: list[str]):
    rows = [{"environment": f"env-{index}", "missing_secrets": [], "missing_vars": []} for index in range(12)]
    rows[0] = {"environment": "env-0", "missing_secrets": missing_secret, "missing_vars": missing_var}
    return {"schema": 1, "kind": "psmatrix.production-ga-environment-inventory-audit", "version": "2.0.0", "environment_count": 12, "required_check_count": 41, "environments": rows}


class PartialProvisioningSelectorTests(unittest.TestCase):
    def test_default_rejects_mixed_present_and_missing_material_in_one_environment(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "/tmp/a", "B": "/tmp/b"}, "vars": {"C": "/tmp/c"}}}}
        with self.assertRaisesRegex(module.ProvisioningSelectionError, "mixed present/missing material"):
            module.select_missing(material, audit(["B"], ["C"]))

    def test_explicit_mixed_environment_mode_preserves_missing_only_selection(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "/tmp/a", "B": "/tmp/b"}, "vars": {"C": "/tmp/c"}}}}
        value = module.select_missing(material, audit(["B"], ["C"]), allow_mixed_environment=True)
        self.assertEqual(value["check_count"], 2)
        self.assertEqual(set(value["environments"]["env-0"]["secrets"]), {"B"})
        self.assertEqual(set(value["environments"]["env-0"]["vars"]), {"C"})
        self.assertEqual(value["selection"]["already_present_checks_skipped"], 1)
        self.assertTrue(value["selection"]["mixed_environment_selection_allowed"])
        self.assertFalse(value["safety"]["production_readiness_claimed"])

    def test_fully_missing_mapped_environment_remains_selectable_by_default(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "/tmp/a", "B": "/tmp/b"}, "vars": {"C": "/tmp/c"}}}}
        value = module.select_missing(material, audit(["A", "B"], ["C"]))
        self.assertEqual(value["check_count"], 3)
        self.assertEqual(value["selection"]["already_present_checks_skipped"], 0)
        self.assertFalse(value["selection"]["mixed_environment_selection_allowed"])

    def test_zero_missing_prepared_checks_fails_closed(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "/tmp/a"}, "vars": {}}}}
        with self.assertRaises(module.ProvisioningSelectionError):
            module.select_missing(material, audit([], []))

    def test_duplicate_inventory_environment_fails_closed(self):
        value = audit(["A"], [])
        value["environments"][1]["environment"] = "env-0"
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "/tmp/a"}, "vars": {}}}}
        with self.assertRaises(module.ProvisioningSelectionError):
            module.select_missing(material, value)


if __name__ == "__main__":
    unittest.main()
