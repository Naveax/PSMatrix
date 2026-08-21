from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_AUTH_SCRIPT = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"
OTLP_SCRIPT = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class External22ProvisioningPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_auth = load(PUBLIC_AUTH_SCRIPT, "external22_public_auth_path_safety")
        cls.otlp = load(OTLP_SCRIPT, "external22_otlp_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_public_auth_material_root_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-root-symlink-") as temporary:
            root = Path(temporary)
            target = root / "material-target"
            target.mkdir()
            link = root / "material"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.public_auth.PublicAuthProvisioningError,
                "public-auth material root is missing or unsafe",
            ):
                self.public_auth.validate_material(link)

    def test_otlp_headers_file_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-headers-symlink-") as temporary:
            root = Path(temporary)
            target = root / "headers-target.json"
            target.write_text(json.dumps({"Authorization": "Bearer sentinel"}) + "\n", encoding="utf-8")
            link = root / "headers.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.otlp.OTLPProvisioningError,
                "OTLP headers file is missing or unsafe",
            ):
                self.otlp.validate_provisioning("https://collector.example.invalid/v1/traces", link)

    def test_otlp_regular_headers_file_remains_valid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-headers-regular-") as temporary:
            root = Path(temporary)
            headers = root / "headers.json"
            headers.write_text(
                json.dumps({"Authorization": "Bearer sentinel", "X-Tenant": "test"}) + "\n",
                encoding="utf-8",
            )
            result = self.otlp.validate_provisioning(
                "https://collector.example.invalid/v1/traces",
                headers,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["endpoint_scheme"], "https")
            self.assertEqual(result["header_count"], 2)
            self.assertFalse(result["network_probe_executed"])


if __name__ == "__main__":
    unittest.main()
