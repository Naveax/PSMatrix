from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_AUTH_SCRIPT = ROOT / "scripts" / "ga" / "probe_public_auth.py"
OTLP_SCRIPT = ROOT / "scripts" / "ga" / "probe_external_otlp.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


class External22LegacyProbePathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_auth = load(PUBLIC_AUTH_SCRIPT, "external22_legacy_public_auth_path_safety")
        cls.otlp = load(OTLP_SCRIPT, "external22_legacy_otlp_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_public_auth_safe_file_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-public-auth-file-") as temporary:
            root = Path(temporary)
            target = root / "client.pem"
            target.write_text("sentinel\n", encoding="utf-8")
            link = root / "client-link.pem"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.public_auth.ProbeError, "symlink component"):
                self.public_auth._safe_file(link, "client certificate")

    def test_public_auth_safe_file_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-public-auth-parent-") as temporary:
            root = Path(temporary)
            target_dir = root / "material-target"
            target_dir.mkdir()
            (target_dir / "client.pem").write_text("sentinel\n", encoding="utf-8")
            link_dir = root / "material"
            self._symlink_or_skip(link_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(self.public_auth.ProbeError, "symlink component"):
                self.public_auth._safe_file(link_dir / "client.pem", "client certificate")

    def test_public_auth_output_directory_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-public-auth-output-") as temporary:
            root = Path(temporary)
            target_dir = root / "output-target"
            target_dir.mkdir()
            link_dir = root / "output"
            self._symlink_or_skip(link_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(self.public_auth.ProbeError, "symlink component"):
                self.public_auth._safe_output_directory(link_dir / "nested", "public-auth probe output directory")

    def test_otlp_output_directory_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-otlp-output-") as temporary:
            root = Path(temporary)
            target_dir = root / "output-target"
            target_dir.mkdir()
            link_dir = root / "output"
            self._symlink_or_skip(link_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(self.otlp.ProbeError, "symlink component"):
                self.otlp._safe_output_directory(link_dir, "external OTLP probe output directory")

    def test_otlp_atomic_json_rejects_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-otlp-json-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "report.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.otlp.ProbeError, "symlink component"):
                self.otlp.atomic_json(link, {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "{}\n")


if __name__ == "__main__":
    unittest.main()
