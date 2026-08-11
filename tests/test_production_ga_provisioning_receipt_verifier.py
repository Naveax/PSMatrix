from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_ga_provisioning_receipt.py"
spec = importlib.util.spec_from_file_location("receipt", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def audit(missing_secrets=None, missing_vars=None):
    rows = [{"environment": f"env-{i}", "required": 1, "present": 1, "missing_secrets": [], "missing_vars": []} for i in range(12)]
    rows[0].update({"required": 3, "present": 3 - len(missing_secrets or []) - len(missing_vars or []), "missing_secrets": missing_secrets or [], "missing_vars": missing_vars or []})
    return {"schema": 1, "kind": "psmatrix.production-ga-environment-inventory-audit", "version": "2.0.0", "required_check_count": 41, "environments": rows}


class ProvisioningReceiptVerifierTests(unittest.TestCase):
    def test_planned_names_present_after_provisioning_pass(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "external-a"}, "vars": {"B": "external-b"}}}}
        value = module.verify(material, audit())
        self.assertEqual(value["verified_check_count"], 2)
        self.assertTrue(all(item["present_after_provisioning"] for item in value["checks"]))
        self.assertFalse(value["secret_values_observed"])
        self.assertFalse(value["ga_eligible"])

    def test_still_missing_planned_name_fails_closed(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {"A": "external-a"}, "vars": {}}}}
        with self.assertRaises(module.ProvisioningReceiptError):
            module.verify(material, audit(missing_secrets=["A"]))

    def test_zero_check_receipt_is_rejected(self):
        material = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "environments": {"env-0": {"secrets": {}, "vars": {}}}}
        with self.assertRaises(module.ProvisioningReceiptError):
            module.verify(material, audit())


if __name__ == "__main__":
    unittest.main()
