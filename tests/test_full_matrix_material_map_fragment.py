from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "ga" / "Initialize-ProductionGAFullMatrixPaths.ps1"
SCRIPT = ROOT / "scripts" / "ga" / "build_full_matrix_material_map_fragment.py"


def load():
    spec = importlib.util.spec_from_file_location("full_matrix_fragment", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FullMatrixMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 required")

    def _receipt(self, root: Path) -> Path:
        receipt = root / "receipt.json"
        completed = subprocess.run(
            [
                str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(BOOTSTRAP),
                "-Root", str(root / "matrix"), "-Output", str(receipt),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        return receipt

    def test_builds_exact_two_variable_fragment_from_real_bootstrap_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-") as temporary:
            root = Path(temporary)
            value = self.module.build_fragment(self._receipt(root), root / "values")
            self.assertEqual(value["environment_count"], 1)
            self.assertEqual(value["check_count"], 2)
            entry = value["environments"]["production-ga-full-matrix"]
            self.assertEqual(entry["secrets"], {})
            self.assertEqual(set(entry["vars"]), {"PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT", "PSMATRIX_FULL_MATRIX_HOME"})
            for path in entry["vars"].values():
                self.assertTrue(Path(path).is_file())

    def test_tampered_path_marker_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            target = Path(data["variables"]["PSMATRIX_FULL_MATRIX_HOME"]) / ".psmatrix-production-ga-path.json"
            target.write_text("{}", encoding="utf-8")
            with self.assertRaises(self.module.FullMatrixFragmentError):
                self.module.build_fragment(receipt, root / "values")

    def test_refuses_repo_local_value_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-") as temporary:
            receipt = self._receipt(Path(temporary))
            with self.assertRaises(self.module.FullMatrixFragmentError):
                self.module.build_fragment(receipt, ROOT / ".tmp-full-matrix-values")

    def test_receipt_cannot_redirect_runtime_path_into_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-repo-path-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            data["variables"]["PSMATRIX_FULL_MATRIX_HOME"] = str(ROOT / ".tmp-full-matrix-home")
            receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")
            output = root / "values"
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must stay outside repository"):
                self.module.build_fragment(receipt, output)
            self.assertFalse(output.exists())

    def test_duplicate_runtime_paths_fail_before_material_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-duplicate-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            data["variables"]["PSMATRIX_FULL_MATRIX_HOME"] = data["variables"]["PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT"]
            receipt.write_text(json.dumps(data) + "\n", encoding="utf-8")
            output = root / "values"
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must be distinct"):
                self.module.build_fragment(receipt, output)
            self.assertFalse(output.exists())

    def test_hardlinked_receipt_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-receipt-hardlink-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            alias = root / "receipt-alias.json"
            try:
                os.link(receipt, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must not be hardlinked"):
                self.module.build_fragment(receipt, root / "values")

    def test_hardlinked_marker_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-marker-hardlink-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            marker = Path(data["variables"]["PSMATRIX_FULL_MATRIX_HOME"]) / ".psmatrix-production-ga-path.json"
            target = root / "marker-target.json"
            try:
                target.write_bytes(marker.read_bytes())
                marker.unlink()
                os.link(target, marker)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must not be hardlinked"):
                self.module.build_fragment(receipt, root / "values")

    def test_hardlinked_value_output_is_rejected_before_any_material_write_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-value-hardlink-") as temporary:
            root = Path(temporary)
            receipt = self._receipt(root)
            output = root / "values"
            output.mkdir()
            targets: list[Path] = []
            aliases: list[Path] = []
            try:
                for name in ("PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT", "PSMATRIX_FULL_MATRIX_HOME"):
                    target = root / f"target-{name}.txt"
                    alias = output / f"{name}.txt"
                    target.write_text("sentinel\n", encoding="utf-8")
                    os.link(target, alias)
                    targets.append(target)
                    aliases.append(alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must not be hardlinked"):
                self.module.build_fragment(receipt, output)
            self.assertTrue(all(target.read_text(encoding="utf-8") == "sentinel\n" for target in targets))

    def test_hardlinked_output_map_is_rejected_without_target_mutation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-map-hardlink-") as temporary:
            root = Path(temporary)
            value = self.module.build_fragment(self._receipt(root), root / "values")
            target = root / "target-map.json"
            output = root / "map.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.FullMatrixFragmentError, "must not be hardlinked"):
                self.module.write_fragment(output, value)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_validates_inputs_before_atomic_material_writes(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("receipt_file = _safe_regular_file", source)
        self.assertIn("_safe_external_directory(Path(str(raw))", source)
        self.assertIn("physical_runtime_paths", source)
        self.assertIn("len(set(physical_runtime_paths)) != 2", source)
        self.assertLess(source.index("len(set(physical_runtime_paths)) != 2"), source.index("atomic_write_text(value_file"))
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(map_path, value)", source)


if __name__ == "__main__":
    unittest.main()
