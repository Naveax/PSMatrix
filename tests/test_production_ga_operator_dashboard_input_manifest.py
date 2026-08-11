from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "render_production_ga_operator_dashboard.py"


def load_module():
    spec = importlib.util.spec_from_file_location("production_ga_dashboard_input_manifest", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(present: int = 0) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-inventory-audit",
        "version": "2.0.0",
        "environment_count": 12,
        "required_check_count": 41,
        "present_check_count": present,
        "missing_check_count": 41 - present,
    }


def summary(passed: bool = False) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary",
        "version": "2.0.0",
        "environment_count": 12,
        "status": "PASS" if passed else "FAIL",
        "environment_passed": 12 if passed else 0,
        "environment_failed": 0 if passed else 12,
        "environment_readiness": passed,
    }


def manifest() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-operator-dashboard-input-manifest",
        "version": "2.0.0",
        "required": {
            "inventory_audit": "inventory.json",
            "readiness_summary": "readiness.json",
        },
        "optional": {},
        "single_content_operations": [],
    }


class ProductionGAOperatorDashboardInputManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "inventory.json").write_text(json.dumps(inventory()) + "\n", encoding="utf-8")
        (self.root / "readiness.json").write_text(json.dumps(summary()) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_minimal_manifest_delegates_to_repository_dashboard(self) -> None:
        value = self.module.render(manifest(), self.root)
        self.assertEqual(value["kind"], "psmatrix.production-ga-operator-dashboard")
        self.assertEqual(value["stage"], "PROVISION_ENVIRONMENTS")
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_same_receipt_cannot_satisfy_two_roles(self) -> None:
        value = manifest()
        value["optional"] = {"readiness_verification": "inventory.json"}
        with self.assertRaises(self.module.OperatorDashboardInputManifestError):
            self.module.render(value, self.root)

    def test_parent_absolute_windows_and_backslash_paths_are_rejected(self) -> None:
        for bad in ("../inventory.json", "/tmp/inventory.json", "C:/inventory.json", "folder\\inventory.json"):
            value = manifest()
            value["required"] = {
                "inventory_audit": bad,
                "readiness_summary": "readiness.json",
            }
            with self.subTest(path=bad):
                with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                    self.module.render(value, self.root)

    def test_symlink_receipt_is_rejected(self) -> None:
        target = self.root / "inventory.json"
        link = self.root / "inventory-link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        value = manifest()
        value["required"] = {
            "inventory_audit": "inventory-link.json",
            "readiness_summary": "readiness.json",
        }
        with self.assertRaises(self.module.OperatorDashboardInputManifestError):
            self.module.render(value, self.root)

    def test_unknown_manifest_roles_and_too_many_single_receipts_fail(self) -> None:
        value = manifest()
        value["optional"] = {"invented_receipt": "inventory.json"}
        with self.assertRaises(self.module.OperatorDashboardInputManifestError):
            self.module.render(value, self.root)
        value = manifest()
        value["single_content_operations"] = ["inventory.json"] * 10
        with self.assertRaises(self.module.OperatorDashboardInputManifestError):
            self.module.render(value, self.root)

    def test_duplicate_json_keys_are_rejected_before_render(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema":1,"schema":1,"kind":"psmatrix.production-ga-operator-dashboard-input-manifest","version":"2.0.0","required":{},"optional":{},"single_content_operations":[]}\n',
            encoding="utf-8",
        )
        with self.assertRaises(self.module.OperatorDashboardInputManifestError):
            self.module._read_json(duplicate, "dashboard input manifest")

    def test_receipt_root_inside_repository_is_rejected(self) -> None:
        forbidden = ROOT / ".tmp-dashboard-receipts"
        forbidden.mkdir(exist_ok=True)
        try:
            with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                self.module._external_receipt_root(forbidden)
        finally:
            forbidden.rmdir()

    def test_source_uses_repository_dashboard_without_shelling_out(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_production_ga_operator_dashboard.py", text)
        self.assertIn("object_pairs_hook=_unique_object", text)
        self.assertIn("one receipt file may not satisfy multiple dashboard roles", text)
        self.assertIn("receipt root must stay outside repository", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
