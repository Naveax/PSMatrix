from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("external_otlp_provisioning", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load external OTLP provisioning validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExternalOTLPProvisioningValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _headers_file(self, root: Path, value: dict[str, str]) -> Path:
        path = root / "headers.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_accepts_https_endpoint_and_secret_headers_without_serializing_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-") as temporary:
            headers = {"Authorization": "Bearer extremely-secret-token", "X-PSMatrix-Tenant": "ga-final"}
            value = self.module.validate_provisioning(
                "https://otel.example.test/v1/traces",
                self._headers_file(Path(temporary), headers),
            )
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["required_check_count"], 2)
            self.assertEqual(value["endpoint_scheme"], "https")
            self.assertEqual(value["header_count"], 2)
            self.assertEqual(value["header_names"], ["Authorization", "X-PSMatrix-Tenant"])
            self.assertFalse(value["network_probe_executed"])
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("extremely-secret-token", serialized)
            self.assertNotIn("ga-final", serialized)
            self.assertFalse(value["safety"]["header_values_serialized"])

    def test_rejects_http_endpoint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-") as temporary:
            headers = self._headers_file(Path(temporary), {"Authorization": "Bearer token"})
            with self.assertRaises(self.module.OTLPProvisioningError):
                self.module.validate_provisioning("http://otel.example.test/v1/traces", headers)

    def test_rejects_endpoint_embedded_credentials(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-") as temporary:
            headers = self._headers_file(Path(temporary), {"Authorization": "Bearer token"})
            with self.assertRaises(self.module.OTLPProvisioningError):
                self.module.validate_provisioning("https://user:pass@otel.example.test/v1/traces", headers)

    def test_rejects_header_injection_and_case_insensitive_duplicates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-") as temporary:
            root = Path(temporary)
            injected = self._headers_file(root, {"Authorization": "Bearer token\r\nX-Evil: yes"})
            with self.assertRaises(self.module.OTLPProvisioningError):
                self.module.validate_provisioning("https://otel.example.test/v1/traces", injected)
            duplicated = self._headers_file(root, {"Authorization": "Bearer one", "authorization": "Bearer two"})
            with self.assertRaises(self.module.OTLPProvisioningError):
                self.module.validate_provisioning("https://otel.example.test/v1/traces", duplicated)


if __name__ == "__main__":
    unittest.main()
