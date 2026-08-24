from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "materialize_verified_evidence_artifact.py"


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


class EvidenceArtifactMaterializerPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.materializer = load(SCRIPT, "ga_evidence_artifact_materializer_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def _archive(self, root: Path) -> Path:
        archive = root / "artifact.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("evidence/result.json", '{"status":"PASS"}\n')
        return archive

    def test_api_verification_input_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-materializer-api-") as temporary:
            root = Path(temporary)
            target = root / "verification.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "verification-link.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.materializer.EvidenceArtifactMaterializationError,
                "API verification input contains a symlink component",
            ):
                self.materializer._safe_input_file(link, "API verification input")

    def test_receipt_output_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-materializer-receipt-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("sentinel\n", encoding="utf-8")
            link = root / "receipt.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.materializer.EvidenceArtifactMaterializationError,
                "materialization receipt contains a symlink component",
            ):
                self.materializer._safe_output_file(link, "materialization receipt")
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_safe_extract_rejects_direct_destination_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-materializer-destination-") as temporary:
            root = Path(temporary)
            archive = self._archive(root)
            target_dir = root / "destination-target"
            target_dir.mkdir()
            link_dir = root / "destination"
            self._symlink_or_skip(link_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.materializer.EvidenceArtifactMaterializationError,
                "artifact destination contains a symlink component",
            ):
                self.materializer.safe_extract(archive, link_dir)
            self.assertEqual(list(target_dir.iterdir()), [])

    def test_safe_extract_rejects_parent_destination_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-materializer-parent-") as temporary:
            root = Path(temporary)
            archive = self._archive(root)
            target_dir = root / "destination-target"
            target_dir.mkdir()
            link_dir = root / "destination-parent"
            self._symlink_or_skip(link_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.materializer.EvidenceArtifactMaterializationError,
                "artifact destination contains a symlink component",
            ):
                self.materializer.safe_extract(archive, link_dir / "nested")
            self.assertEqual(list(target_dir.iterdir()), [])

    def test_safe_extract_regular_destination_still_materializes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-materializer-positive-") as temporary:
            root = Path(temporary)
            archive = self._archive(root)
            destination = root / "destination"
            state = self.materializer.safe_extract(archive, destination)
            self.assertEqual(state["file_count"], 1)
            self.assertEqual((destination / "evidence" / "result.json").read_text(encoding="utf-8"), '{"status":"PASS"}\n')


if __name__ == "__main__":
    unittest.main()
