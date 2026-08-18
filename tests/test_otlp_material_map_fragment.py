from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_otlp_material_map_fragment.py"


def load():
    spec = importlib.util.spec_from_file_location("otlp_fragment", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OTLPProvisioningMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()

    def _sources(self, root: Path) -> tuple[Path, Path]:
        endpoint = root / "endpoint.txt"
        headers = root / "headers.json"
        endpoint.write_text("https://otel.example.test/v1/traces\n", encoding="utf-8")
        headers.write_text(
            json.dumps({
                "Authorization": "Bearer secret-otlp-token",
                "X-PSMatrix-Tenant": "tenant-fixture-secret-value",
            }),
            encoding="utf-8",
        )
        return endpoint, headers

    def test_valid_otlp_material_builds_exact_one_secret_one_variable_fragment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
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
            self.assertFalse(value["validation"]["network_probe_executed"])

    def test_header_injection_is_rejected_by_existing_validator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            headers.write_text(json.dumps({"Authorization": "Bearer token\r\nX-Evil: yes"}), encoding="utf-8")
            with self.assertRaises(self.module.OTLPFragmentError):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_non_https_endpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            endpoint.write_text("http://otel.example.test/v1/traces\n", encoding="utf-8")
            with self.assertRaises(self.module.OTLPFragmentError):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_repo_local_value_output_is_rejected_before_directory_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-fragment-") as temporary:
            endpoint, headers = self._sources(Path(temporary))
            forbidden_root = ROOT / ".tmp-otlp-values"
            try:
                with self.assertRaises(self.module.OTLPFragmentError):
                    self.module.build_fragment(endpoint, headers, forbidden_root / "nested")
                self.assertFalse(forbidden_root.exists())
            finally:
                if forbidden_root.exists():
                    shutil.rmtree(forbidden_root)

    def test_hardlinked_endpoint_source_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-endpoint-hardlink-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            alias = root / "endpoint-alias.txt"
            try:
                os.link(endpoint, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.OTLPFragmentError, "must not be hardlinked"):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_hardlinked_headers_source_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-headers-hardlink-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            alias = root / "headers-alias.json"
            try:
                os.link(headers, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.OTLPFragmentError, "must not be hardlinked"):
                self.module.build_fragment(endpoint, headers, root / "values")

    def test_hardlinked_normalized_endpoint_output_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-value-hardlink-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            output = root / "values"
            output.mkdir()
            target = root / "target-endpoint.txt"
            alias = output / "PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT.txt"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.OTLPFragmentError, "must not be hardlinked"):
                self.module.build_fragment(endpoint, headers, output)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_hardlinked_output_map_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-map-hardlink-") as temporary:
            root = Path(temporary)
            endpoint, headers = self._sources(root)
            value = self.module.build_fragment(endpoint, headers, root / "values")
            target = root / "target-map.json"
            output = root / "map.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.OTLPFragmentError, "must not be hardlinked"):
                self.module.write_fragment(output, value)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_uses_lstat_hardlink_checks_and_atomic_writers(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_text(normalized_endpoint", source)
        self.assertIn("atomic_write_json(output, value)", source)


if __name__ == "__main__":
    unittest.main()
