from __future__ import annotations

import importlib.util
import json
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
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class FullMatrixMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 required")

    def _receipt(self, root: Path) -> Path:
        receipt = root / "receipt.json"
        completed = subprocess.run([str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(BOOTSTRAP), "-Root", str(root / "matrix"), "-Output", str(receipt)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=30)
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
            root = Path(temporary); receipt = self._receipt(root)
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            target = Path(data["variables"]["PSMATRIX_FULL_MATRIX_HOME"]) / ".psmatrix-production-ga-path.json"
            target.write_text('{}', encoding='utf-8')
            with self.assertRaises(self.module.FullMatrixFragmentError):
                self.module.build_fragment(receipt, root / "values")

    def test_refuses_repo_local_value_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-fragment-") as temporary:
            receipt = self._receipt(Path(temporary))
            with self.assertRaises(self.module.FullMatrixFragmentError):
                self.module.build_fragment(receipt, ROOT / ".tmp-full-matrix-values")


if __name__ == "__main__":
    unittest.main()
