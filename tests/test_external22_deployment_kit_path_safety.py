from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "public_auth_deployment_kit.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class External22DeploymentKitPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kit = load(SCRIPT, "external22_deployment_kit_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_safe_file_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-deploy-key-symlink-") as temporary:
            root = Path(temporary)
            target = root / "key-target.pem"
            target.write_text("sentinel\n", encoding="utf-8")
            link = root / "key.pem"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.kit.DeploymentKitError,
                "deployment authority private key contains a symlink component",
            ):
                self.kit._safe_file(link, "deployment authority private key")

    def test_safe_file_rejects_parent_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-deploy-parent-symlink-") as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (real / "key.pem").write_text("sentinel\n", encoding="utf-8")
            link = root / "linked"
            self._symlink_or_skip(link, real, target_is_directory=True)
            with self.assertRaisesRegex(self.kit.DeploymentKitError, "contains a symlink component"):
                self.kit._safe_file(link / "key.pem", "deployment authority public key")

    def test_safe_output_rejects_direct_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-deploy-output-symlink-") as temporary:
            root = Path(temporary)
            target = root / "target.zip"
            target.write_bytes(b"sentinel")
            output = root / "kit.zip"
            self._symlink_or_skip(output, target)
            with self.assertRaisesRegex(self.kit.DeploymentKitError, "contains a symlink component"):
                self.kit._safe_output(output, "deployment kit output")
            self.assertEqual(target.read_bytes(), b"sentinel")

    def test_verify_rejects_symlink_kit_before_archive_parsing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-deploy-verify-symlink-") as temporary:
            root = Path(temporary)
            kit_target = root / "kit-target.zip"
            kit_target.write_bytes(b"not-a-zip")
            kit_link = root / "kit.zip"
            self._symlink_or_skip(kit_link, kit_target)
            public_key = root / "public.pem"
            public_key.write_text("not-used\n", encoding="utf-8")
            args = SimpleNamespace(
                kit=kit_link,
                public_key=public_key,
                expected_release_commit=None,
                expected_version=None,
                expected_release_manifest_sha256=None,
                expected_wheel_sha256=None,
                output=None,
            )
            with self.assertRaisesRegex(self.kit.DeploymentKitError, "deployment kit contains a symlink component"):
                self.kit.verify(args)


if __name__ == "__main__":
    unittest.main()
