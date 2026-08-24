from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_AUTH = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"
OTLP = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class External22ProvisioningParentPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_auth = load(PUBLIC_AUTH, "external22_public_auth_parent_path_safety")
        cls.otlp = load(OTLP, "external22_otlp_parent_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_public_auth_material_root_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-parent-") as temporary:
            root = Path(temporary)
            target_parent = root / "target-parent"
            target_parent.mkdir()
            material = target_parent / "material"
            material.mkdir()
            alias_parent = root / "alias-parent"
            self._symlink_or_skip(alias_parent, target_parent, target_is_directory=True)
            with self.assertRaisesRegex(
                self.public_auth.PublicAuthProvisioningError,
                "public-auth material root contains a link or reparse component",
            ):
                self.public_auth.validate_material(alias_parent / "material")

    def test_otlp_headers_reject_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-parent-") as temporary:
            root = Path(temporary)
            target_parent = root / "target-parent"
            target_parent.mkdir()
            headers = target_parent / "headers.json"
            headers.write_text('{"Authorization":"Bearer sentinel"}\n', encoding="utf-8")
            alias_parent = root / "alias-parent"
            self._symlink_or_skip(alias_parent, target_parent, target_is_directory=True)
            with self.assertRaisesRegex(
                self.otlp.OTLPProvisioningError,
                "OTLP headers file contains a link or reparse component",
            ):
                self.otlp.validate_provisioning(
                    "https://collector.example.invalid/v1/traces",
                    alias_parent / "headers.json",
                )

    def test_public_auth_output_rejects_direct_symlink_without_mutating_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-output-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("sentinel\n", encoding="utf-8")
            output = root / "output.json"
            self._symlink_or_skip(output, target)
            with self.assertRaisesRegex(
                self.public_auth.PublicAuthProvisioningError,
                "public-auth provisioning validation output contains a link or reparse component",
            ):
                self.public_auth._safe_output_file(
                    output,
                    label="public-auth provisioning validation output",
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_otlp_output_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-output-parent-") as temporary:
            root = Path(temporary)
            target_parent = root / "target-parent"
            target_parent.mkdir()
            alias_parent = root / "alias-parent"
            self._symlink_or_skip(alias_parent, target_parent, target_is_directory=True)
            with self.assertRaisesRegex(
                self.otlp.OTLPProvisioningError,
                "OTLP provisioning validation output contains a link or reparse component",
            ):
                self.otlp._safe_output_file(
                    alias_parent / "status.json",
                    label="OTLP provisioning validation output",
                )

    def test_validators_explicitly_check_windows_reparse_attributes(self) -> None:
        for path in (PUBLIC_AUTH, OTLP):
            raw = path.read_text(encoding="utf-8")
            self.assertIn("st_file_attributes", raw)
            self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", raw)
            self.assertIn("_reject_link_or_reparse_components", raw)
            self.assertIn("link_or_reparse_components_allowed", raw)


if __name__ == "__main__":
    unittest.main()
