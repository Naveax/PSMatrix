from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_AUTH_SCRIPT = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"
OTLP_SCRIPT = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"
PUBLIC_AUTH_BIND_SCRIPT = ROOT / "scripts" / "ga" / "bind_public_auth_release.py"
OTLP_BIND_SCRIPT = ROOT / "scripts" / "ga" / "bind_external_otlp_release.py"
PUBLIC_AUTH_ENFORCE_SCRIPT = ROOT / "scripts" / "ga" / "enforce_public_auth_report.py"
OTLP_ENFORCE_SCRIPT = ROOT / "scripts" / "ga" / "enforce_external_otlp_report.py"


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
        cls.public_auth_bind = load(PUBLIC_AUTH_BIND_SCRIPT, "external22_public_auth_bind_path_safety")
        cls.otlp_bind = load(OTLP_BIND_SCRIPT, "external22_otlp_bind_path_safety")
        cls.public_auth_enforce = load(PUBLIC_AUTH_ENFORCE_SCRIPT, "external22_public_auth_enforce_path_safety")
        cls.otlp_enforce = load(OTLP_ENFORCE_SCRIPT, "external22_otlp_enforce_path_safety")

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

    def test_otlp_release_binding_main_preserves_symlink_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bind-input-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            report = root / "report.json"
            self._symlink_or_skip(report, target)
            proof = root / "proof.json"
            proof.write_text("{}\n", encoding="utf-8")
            original = self.otlp_bind.parse_args
            self.otlp_bind.parse_args = lambda: SimpleNamespace(
                report=report,
                proof=proof,
                release_commit="0" * 40,
                expected_version="2.0.0",
                release_manifest_sha256="1" * 64,
                release_wheel_sha256="2" * 64,
                output=None,
            )
            try:
                with self.assertRaisesRegex(
                    self.otlp_bind.BindingError,
                    "external OTLP live report is missing or unsafe",
                ):
                    self.otlp_bind.main()
            finally:
                self.otlp_bind.parse_args = original

    def test_public_auth_release_binding_main_preserves_symlink_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-bind-input-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            report = root / "report.json"
            self._symlink_or_skip(report, target)
            oauth = root / "oauth.json"
            mtls = root / "mtls.json"
            oauth.write_text("{}\n", encoding="utf-8")
            mtls.write_text("{}\n", encoding="utf-8")
            original = self.public_auth_bind.parse_args
            self.public_auth_bind.parse_args = lambda: SimpleNamespace(
                report=report,
                oauth_proof=oauth,
                mtls_proof=mtls,
                release_commit="0" * 40,
                expected_version="2.0.0",
                release_manifest_sha256="1" * 64,
                release_wheel_sha256="2" * 64,
                output=None,
            )
            try:
                with self.assertRaisesRegex(
                    self.public_auth_bind.BindingError,
                    "live report is missing or unsafe",
                ):
                    self.public_auth_bind.main()
            finally:
                self.public_auth_bind.parse_args = original

    def test_otlp_release_binding_refuses_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bind-output-symlink-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("sentinel\n", encoding="utf-8")
            output = root / "output.json"
            self._symlink_or_skip(output, target)
            with self.assertRaisesRegex(self.otlp_bind.BindingError, "JSON output path is unsafe"):
                self.otlp_bind.atomic_json(output, {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_public_auth_release_binding_refuses_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-bind-output-symlink-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("sentinel\n", encoding="utf-8")
            output = root / "output.json"
            self._symlink_or_skip(output, target)
            with self.assertRaisesRegex(self.public_auth_bind.BindingError, "JSON output path is unsafe"):
                self.public_auth_bind.atomic_json(output, {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_otlp_enforcement_main_preserves_symlink_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-enforce-input-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            report = root / "report.json"
            self._symlink_or_skip(report, target)
            proof = root / "proof.json"
            proof.write_text("{}\n", encoding="utf-8")
            original = self.otlp_enforce.parse_args
            self.otlp_enforce.parse_args = lambda: SimpleNamespace(
                report=report,
                proof=proof,
                release_commit="0" * 40,
                expected_version="2.0.0",
                release_manifest_sha256="1" * 64,
                release_wheel_sha256="2" * 64,
            )
            try:
                with self.assertRaisesRegex(
                    self.otlp_enforce.EnforcementError,
                    "external OTLP live report is missing or unsafe",
                ):
                    self.otlp_enforce.main()
            finally:
                self.otlp_enforce.parse_args = original

    def test_public_auth_enforcement_main_preserves_symlink_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-enforce-input-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            report = root / "report.json"
            self._symlink_or_skip(report, target)
            oauth = root / "oauth.json"
            mtls = root / "mtls.json"
            oauth.write_text("{}\n", encoding="utf-8")
            mtls.write_text("{}\n", encoding="utf-8")
            original = self.public_auth_enforce.parse_args
            self.public_auth_enforce.parse_args = lambda: SimpleNamespace(
                report=report,
                oauth_proof=oauth,
                mtls_proof=mtls,
                release_commit="0" * 40,
                expected_version="2.0.0",
                release_manifest_sha256="1" * 64,
                release_wheel_sha256="2" * 64,
            )
            try:
                with self.assertRaisesRegex(
                    self.public_auth_enforce.EnforcementError,
                    "live report is missing or unsafe",
                ):
                    self.public_auth_enforce.main()
            finally:
                self.public_auth_enforce.parse_args = original


if __name__ == "__main__":
    unittest.main()
