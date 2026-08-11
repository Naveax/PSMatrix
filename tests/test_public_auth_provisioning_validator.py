from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPT = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"

from psmatrix.pki import create_ca, issue_certificate


def _load_module():
    spec = importlib.util.spec_from_file_location("public_auth_provisioning", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load public-auth provisioning validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicAuthProvisioningValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _make_material(self, root: Path) -> Path:
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
        for index, name in enumerate(self.module.TOKEN_NAMES, 1):
            (secrets / f"{name}.txt").write_text(f"opaque-oauth-fixture-{index}\n", encoding="utf-8")

        ca = create_ca(root / "fixture-ca", common_name="PSMatrix Public Auth Fixture CA", days=30)
        ca_certificate = Path(ca["certificate"])
        ca_private_key = Path(ca["private_key"])
        for index, prefix in enumerate(self.module.PAIR_PREFIXES, 1):
            issued = issue_certificate(
                ca_certificate,
                ca_private_key,
                root / f"fixture-client-{index}",
                common_name=f"psmatrix-fixture-{index}",
                role="client",
                days=1,
            )
            (secrets / f"{prefix}_CERT.pem").write_bytes(Path(issued["certificate"]).read_bytes())
            (secrets / f"{prefix}_KEY.pem").write_bytes(Path(issued["private_key"]).read_bytes())
        return material

    def test_validates_exact_nineteen_public_auth_requirements(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-") as temporary:
            value = self.module.validate_material(self._make_material(Path(temporary)))
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["required_check_count"], 19)
            self.assertEqual(value["oauth_token_count"], 6)
            self.assertEqual(value["mtls_pair_count"], 4)
            self.assertEqual(value["variable_count"], 5)
            self.assertFalse(value["safety"]["secret_values_serialized"])
            self.assertFalse(value["safety"]["secret_hashes_serialized"])

    def test_rejects_mtls_certificate_private_key_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-") as temporary:
            material = self._make_material(Path(temporary))
            secrets = material / "secrets"
            current = secrets / "PSMATRIX_MTLS_CURRENT_KEY.pem"
            current.write_bytes((secrets / "PSMATRIX_MTLS_ROTATION_KEY.pem").read_bytes())
            with self.assertRaises(self.module.PublicAuthProvisioningError):
                self.module.validate_material(material)

    def test_rejects_duplicate_oauth_fixture_tokens(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-") as temporary:
            material = self._make_material(Path(temporary))
            secrets = material / "secrets"
            first = secrets / f"{self.module.TOKEN_NAMES[0]}.txt"
            second = secrets / f"{self.module.TOKEN_NAMES[1]}.txt"
            second.write_bytes(first.read_bytes())
            with self.assertRaises(self.module.PublicAuthProvisioningError):
                self.module.validate_material(material)

    def test_rejects_non_https_endpoint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-") as temporary:
            material = self._make_material(Path(temporary))
            variables = json.loads((material / "vars.json").read_text(encoding="utf-8"))
            variables["PSMATRIX_OAUTH_ENDPOINT"] = "http://auth.example.test/oauth/introspect"
            (material / "vars.json").write_text(json.dumps(variables), encoding="utf-8")
            with self.assertRaises(self.module.PublicAuthProvisioningError):
                self.module.validate_material(material)

    def test_result_serializes_names_only_not_fixture_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-") as temporary:
            material = self._make_material(Path(temporary))
            value = self.module.validate_material(material)
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("opaque-oauth-fixture-", serialized)
            self.assertNotIn("BEGIN CERTIFICATE", serialized)
            self.assertNotIn("BEGIN PRIVATE KEY", serialized)
            self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)


if __name__ == "__main__":
    unittest.main()
