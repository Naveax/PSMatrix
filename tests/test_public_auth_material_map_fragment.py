from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPT = ROOT / "scripts" / "ga" / "build_public_auth_material_map_fragment.py"

from psmatrix.pki import create_ca, issue_certificate


def load():
    spec = importlib.util.spec_from_file_location("public_auth_fragment", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicAuthMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()
        cls.validator = cls.module._load_validator()

    def _material(self, root: Path) -> Path:
        material = root / "material"
        secrets = material / "secrets"
        secrets.mkdir(parents=True)
        variables = {
            "PSMATRIX_OAUTH_ENDPOINT": "https://auth.example.test/oauth/introspect",
            "PSMATRIX_OAUTH_DISCOVERY_URL": "https://auth.example.test/.well-known/openid-configuration",
            "PSMATRIX_OAUTH_EXPECTED_ISSUER": "https://auth.example.test/",
            "PSMATRIX_MTLS_ENDPOINT": "https://mtls.example.test/probe",
            "PSMATRIX_MTLS_FINGERPRINT_HEADER": "X-Client-Cert-SHA256",
        }
        (material / "vars.json").write_text(json.dumps(variables), encoding="utf-8")
        for index, name in enumerate(self.validator.TOKEN_NAMES, 1):
            (secrets / f"{name}.txt").write_text(f"opaque-public-auth-{index}\n", encoding="utf-8")
        ca = create_ca(root / "ca", common_name="PSMatrix Public Auth Fragment CA", days=30)
        for index, prefix in enumerate(self.validator.PAIR_PREFIXES, 1):
            issued = issue_certificate(
                Path(ca["certificate"]),
                Path(ca["private_key"]),
                root / f"client-{index}",
                common_name=f"fragment-{index}",
                role="client",
                days=1,
            )
            (secrets / f"{prefix}_CERT.pem").write_bytes(Path(issued["certificate"]).read_bytes())
            (secrets / f"{prefix}_KEY.pem").write_bytes(Path(issued["private_key"]).read_bytes())
        return material

    def test_valid_material_builds_exact_fourteen_secret_five_variable_fragment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-fragment-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            value = self.module.build_fragment(material, root / "values")
            self.assertEqual(value["environment_count"], 1)
            self.assertEqual(value["check_count"], 19)
            entry = value["environments"]["production-ga-public-auth-probe"]
            self.assertEqual(len(entry["secrets"]), 14)
            self.assertEqual(len(entry["vars"]), 5)
            for path in [*entry["secrets"].values(), *entry["vars"].values()]:
                self.assertTrue(Path(path).is_file())
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("opaque-public-auth-", serialized)
            self.assertNotIn("auth.example.test", serialized)
            self.assertNotIn("BEGIN CERTIFICATE", serialized)
            self.assertNotIn("BEGIN PRIVATE KEY", serialized)

    def test_certificate_private_key_mismatch_is_rejected_by_real_validator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-fragment-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            secrets = material / "secrets"
            (secrets / "PSMATRIX_MTLS_CURRENT_KEY.pem").write_bytes(
                (secrets / "PSMATRIX_MTLS_ROTATION_KEY.pem").read_bytes()
            )
            with self.assertRaises(self.module.PublicAuthFragmentError):
                self.module.build_fragment(material, root / "values")

    def test_repo_local_value_output_is_rejected_before_directory_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-fragment-") as temporary:
            material = self._material(Path(temporary))
            forbidden_root = ROOT / ".tmp-public-auth-values"
            try:
                with self.assertRaises(self.module.PublicAuthFragmentError):
                    self.module.build_fragment(material, forbidden_root / "nested")
                self.assertFalse(forbidden_root.exists())
            finally:
                if forbidden_root.exists():
                    shutil.rmtree(forbidden_root)

    def test_hardlinked_vars_source_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-vars-hardlink-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            vars_path = material / "vars.json"
            alias = root / "vars-alias.json"
            try:
                os.link(vars_path, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.PublicAuthFragmentError, "must not be hardlinked"):
                self.module.build_fragment(material, root / "values")

    def test_hardlinked_secret_source_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-secret-hardlink-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            secret = material / "secrets" / f"{self.validator.TOKEN_NAMES[0]}.txt"
            alias = root / "secret-alias.txt"
            try:
                os.link(secret, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.PublicAuthFragmentError, "must not be hardlinked"):
                self.module.build_fragment(material, root / "values")

    def test_hardlinked_value_output_fails_before_any_variable_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-value-hardlink-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            output = root / "values"
            output.mkdir()
            target = root / "target-value.txt"
            blocked_name = self.validator.VAR_NAMES[-1]
            blocked = output / f"{blocked_name}.txt"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, blocked)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.PublicAuthFragmentError, "must not be hardlinked"):
                self.module.build_fragment(material, output)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
            for name in self.validator.VAR_NAMES[:-1]:
                self.assertFalse((output / f"{name}.txt").exists())

    def test_hardlinked_output_map_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-map-hardlink-") as temporary:
            root = Path(temporary)
            material = self._material(root)
            value = self.module.build_fragment(material, root / "values")
            target = root / "target-map.json"
            output = root / "map.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.PublicAuthFragmentError, "must not be hardlinked"):
                self.module.write_fragment(output, value)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_preflights_all_variable_outputs_before_atomic_writes(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("value_paths = {", source)
        self.assertLess(source.index("value_paths = {"), source.index("atomic_write_text(value_paths[name]"))
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(output, value)", source)


if __name__ == "__main__":
    unittest.main()
