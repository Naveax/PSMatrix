from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_production_environment_provisioning_manifest.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("production_provisioning_manifest", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production provisioning manifest module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionEnvironmentProvisioningManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_manifest_freezes_exact_12_environment_41_check_surface(self) -> None:
        value = self.module.build_manifest(self.contract)
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.production-environment-provisioning-manifest")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["environment_count"], 12)
        self.assertEqual(value["required_check_count"], 41)
        self.assertEqual(value["required_secret_count"], 32)
        self.assertEqual(value["required_var_count"], 9)
        self.assertEqual(value["required_path_var_count"], 2)
        self.assertEqual(len(value["checks"]), 41)
        self.assertEqual(len({(row["environment"], row["source"], row["name"]) for row in value["checks"]}), 41)

    def test_manifest_contains_names_only_and_never_provisioning_values(self) -> None:
        value = self.module.build_manifest(self.contract)
        self.assertEqual(
            value["safety"],
            {
                "secret_values_present": False,
                "secret_hashes_present": False,
                "secret_lengths_present": False,
                "provisioning_values_accepted": False,
            },
        )
        serialized = json.dumps(value, sort_keys=True)
        for marker in (
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ):
            self.assertNotIn(marker, serialized)
        self.assertEqual({row["source"] for row in value["checks"]}, {"secret", "var"})

    def test_all_path_requirements_are_declared_variables(self) -> None:
        value = self.module.build_manifest(self.contract)
        path_vars = []
        for environment in value["environments"]:
            self.assertTrue(set(environment["path_vars"]).issubset(set(environment["required_vars"])))
            path_vars.extend((environment["name"], item) for item in environment["path_vars"])
        self.assertEqual(
            path_vars,
            [
                ("production-ga-full-matrix", "PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT"),
                ("production-ga-full-matrix", "PSMATRIX_FULL_MATRIX_HOME"),
            ],
        )

    def test_duplicate_environment_fails_closed(self) -> None:
        value = json.loads(json.dumps(self.contract))
        value["environments"][1]["name"] = value["environments"][0]["name"]
        with self.assertRaises(self.module.ProvisioningManifestError):
            self.module.build_manifest(value)

    def test_cli_payload_remains_value_free(self) -> None:
        result = self.module.build_manifest(self.contract)
        serialized = json.dumps(result, sort_keys=True)
        self.assertEqual(result["required_check_count"], 41)
        self.assertFalse(result["safety"]["secret_values_present"])
        self.assertNotIn("BEGIN PRIVATE KEY", serialized)

    def test_hardlinked_contract_input_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-provisioning-manifest-contract-hardlink-") as temporary:
            root = Path(temporary)
            source = root / "contract.json"
            alias = root / "contract-alias.json"
            source.write_bytes(CONTRACT.read_bytes())
            try:
                os.link(source, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.ProvisioningManifestError, "must not be hardlinked"):
                self.module._safe_regular_file(source, "production readiness contract")

    def test_hardlinked_output_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-provisioning-manifest-output-hardlink-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            output = root / "manifest.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.ProvisioningManifestError, "must not be hardlinked"):
                self.module._safe_output_file(output)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_output_parent_symlink_or_reparse_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-provisioning-manifest-output-link-") as temporary:
            root = Path(temporary)
            target = root / "target-dir"
            alias = root / "alias-dir"
            target.mkdir()
            try:
                alias.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.ProvisioningManifestError, "links or reparse points"):
                self.module._safe_output_file(alias / "manifest.json")
            self.assertEqual(list(target.iterdir()), [])

    def test_source_uses_lstat_hardlink_checks_and_atomic_output(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(output, result)", source)


if __name__ == "__main__":
    unittest.main()
