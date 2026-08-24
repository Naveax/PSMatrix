from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "assemble_final_ga_evidence.py"


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


class FinalGAEvidenceAssemblerPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assembler = load(SCRIPT, "ga_final_evidence_assembler_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_json_input_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-json-") as temporary:
            root = Path(temporary)
            target = root / "provenance.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "provenance-link.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "Final GA run provenance contains a symlink component",
            ):
                self.assembler._json(link, "Final GA run provenance")

    def test_evidence_root_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-root-") as temporary:
            root = Path(temporary)
            target = root / "evidence-target"
            target.mkdir()
            link = root / "evidence"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "validation-summary evidence root contains a symlink component",
            ):
                self.assembler._require_root(link, "validation-summary")

    def test_evidence_root_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-parent-") as temporary:
            root = Path(temporary)
            target = root / "evidence-target"
            target.mkdir()
            (target / "nested").mkdir()
            link = root / "evidence-parent"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "signed-release evidence root contains a symlink component",
            ):
                self.assembler._require_root(link / "nested", "signed-release")

    def test_evidence_file_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-file-parent-") as temporary:
            root = Path(temporary)
            target = root / "nested-target"
            target.mkdir()
            (target / "report.json").write_text("{}\n", encoding="utf-8")
            link = root / "nested"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "Missing or unsafe validation-summary evidence file",
            ):
                self.assembler._require_file(root, "nested/report.json", "validation-summary")

    def test_public_key_input_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-key-") as temporary:
            root = Path(temporary)
            target = root / "windows-public.pem"
            target.write_text("public-key-placeholder\n", encoding="utf-8")
            link = root / "windows-public-link.pem"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "Windows lab public key contains a symlink component",
            ):
                self.assembler._safe_input_file(link, "Windows lab public key")

    def test_output_root_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-output-") as temporary:
            root = Path(temporary)
            target = root / "output-target"
            target.mkdir()
            link = root / "output"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.assembler.FinalGAEvidenceError,
                "Final GA evidence output contains a symlink component",
            ):
                self.assembler._safe_output_directory(link, "Final GA evidence output")
            self.assertEqual(list(target.iterdir()), [])

    def test_regular_paths_remain_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-assembler-positive-") as temporary:
            root = Path(temporary)
            source = root / "provenance.json"
            source.write_text('{"status":"PASS"}\n', encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            output = root / "output"
            self.assertEqual(self.assembler._json(source, "Final GA run provenance")["status"], "PASS")
            self.assertEqual(self.assembler._require_root(evidence, "validation-summary"), evidence.resolve())
            self.assertEqual(self.assembler._safe_output_directory(output, "Final GA evidence output"), output.resolve())


if __name__ == "__main__":
    unittest.main()
