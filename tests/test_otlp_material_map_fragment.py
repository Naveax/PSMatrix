from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_otlp_material_map_fragment.py"


def load():
    spec = importlib.util.spec_from_file_location("otlp_fragment", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class OTLPProvisioningMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()

    def _sources(self, root: Path) -> tuple[Path, Path]:
        endpoint = root / "endpoint.txt"
        headers = root / "headers.json"
        endpoint.write_text("https://otel.example.test/v1/traces\n", encoding="utf-8")
        headers.write_text(json.dumps({"Authorization": "Bearer secret-otlp-token", "X-PSMatrix-Tenant": "tenant-fixture-secret-value"}), encoding="utf-8")
        return endpoint, headers

    def test_valid_otlp_material_builds_exact_one_secret_one_variable_fragment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary); endpoint, headers = self._sources(root)
            value = self.module.build_fragment(endpoint, headers, root / "values")
            self.assertEqual(value["environment_count"], 1)
            self.assertEqual(value["check_count"], 2)
            entry = value["environments"]["production-ga-external-otlp-probe"]
            self.assertEqual(set(entry["secrets"]), {"PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON"})
            self.assertEqual(set(entry["vars"]), {"PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT"})
            self.assertTrue(Path(entry["secrets"]["PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON"]).samefile(headers))
            endpoint_value_file = Path(entry["vars"]["PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT"])
            self.assertEqual(endpoint_value_file.read_text(encoding="utf-8"), "https://otel.example.test/v1/traces\n")
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("secret-otlp-token", serialized)
            self.assertNotIn("tenant-fixture-secret-value", serialized)
            self.assertNotIn("https://otel.example.test/v1/traces", serialized)
            self.assertEqual(value["environments"].keys(), {"production-ga-external-otlp-probe"})
            self.assertFalse(value["validation"]["network_probe_executed"])

    def test_header_injection_is_rejected_by_existing_validator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary); endpoint, headers = self._sources(root)
            headers.write_text(json.dumps({"Authorization": "Bearer token\r\nX-Evil: yes"}), encoding="utf-8")
            with self.assertRaises(self.module.OTLPFragmentError):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_non_https_endpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary); endpoint, headers = self._sources(root)
            endpoint.write_text("http://otel.example.test/v1/traces\n", encoding="utf-8")
            with self.assertRaises(self.module.OTLPFragmentError):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_repo_local_value_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            endpoint, headers = self._sources(Path(temporary))
            with self.assertRaises(self.module.OTLPFragmentError):
                self.module.build_fragment(endpoint, headers, ROOT / ".tmp-otlp-values")


if __name__ == "__main__":
    unittest.main()
