from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SCRIPT = ROOT / "scripts" / "ga" / "probe_final_public_auth.py"
OTLP_SCRIPT = ROOT / "scripts" / "ga" / "probe_final_external_otlp.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class External22FinalProbePathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public = load(PUBLIC_SCRIPT, "external22_final_public_auth_path_safety")
        cls.otlp = load(OTLP_SCRIPT, "external22_final_otlp_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_public_secret_reader_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-public-token-symlink-") as temporary:
            root = Path(temporary)
            target = root / "token-target.txt"
            target.write_text("secret-token\n", encoding="utf-8")
            link = root / "token.txt"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.public.PublicAuthProbeError, "contains a symlink component"):
                self.public._read_text_secret(link, "OAuth valid token")

    def test_public_signed_release_rejects_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-public-release-symlink-") as temporary:
            root = Path(temporary)
            target = root / "release-target"
            target.mkdir()
            link = root / "release"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(self.public.PublicAuthProbeError, "signed final release root contains a symlink component"):
                self.public._verify_signed_release(link)

    def test_public_proof_result_rejects_report_symlink_before_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-public-report-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "report.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.public.PublicAuthProbeError, "contains a symlink component"):
                self.public.build_proof_result(report_path=link, proof_type="public-oauth", output=root / "proof.json")

    def test_public_output_guard_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-public-output-parent-") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            link = root / "linked"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(self.public.PublicAuthProbeError, "contains a symlink component"):
                self.public._safe_output(link / "proof.json", "public-auth proof-result output")

    def test_otlp_headers_reader_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-headers-symlink-") as temporary:
            root = Path(temporary)
            target = root / "headers-target.json"
            target.write_text(json.dumps({"Authorization": "Bearer sentinel"}) + "\n", encoding="utf-8")
            link = root / "headers.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.otlp.ExternalOTLPProbeError, "contains a symlink component"):
                self.otlp._load_headers(link)

    def test_otlp_release_binding_rejects_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-release-symlink-") as temporary:
            root = Path(temporary)
            target = root / "release-target"
            target.mkdir()
            link = root / "release"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(self.otlp.ExternalOTLPProbeError, "signed final release directory contains a symlink component"):
                self.otlp._release_binding(link, "0" * 40)

    def test_otlp_proof_result_rejects_report_symlink_before_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-report-symlink-") as temporary:
            root = Path(temporary)
            target = root / "report-target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "report.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(self.otlp.ExternalOTLPProbeError, "contains a symlink component"):
                self.otlp.build_proof_result(report_path=link, output=root / "proof.json")

    def test_otlp_home_guard_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-home-parent-") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            link = root / "linked"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(self.otlp.ExternalOTLPProbeError, "contains a symlink component"):
                self.otlp._safe_directory(link / "home", "external OTLP isolated home", create=True)


if __name__ == "__main__":
    unittest.main()
