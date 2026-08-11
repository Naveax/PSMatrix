from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Initialize-ProductionGAFullMatrixPaths.ps1"


class ProductionGAFullMatrixLocalBootstrapTests(unittest.TestCase):
    def _run(self, root: Path, output: Path) -> subprocess.CompletedProcess[str]:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh, "PowerShell 7 is required for Production GA full-matrix bootstrap tests")
        return subprocess.run(
            [str(pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT), "-Root", str(root), "-Output", str(output)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )

    def test_bootstrap_creates_exact_two_required_directories_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bootstrap-") as temporary:
            root = Path(temporary) / "full-matrix"
            output = Path(temporary) / "receipt.json"
            completed = self._run(root, output)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("production_ga_full_matrix_local_paths=PASS", completed.stdout)
            endpoint = root / "endpoint-root"
            home = root / "home"
            self.assertTrue(endpoint.is_dir())
            self.assertTrue(home.is_dir())
            receipt = json.loads(output.read_text(encoding="utf-8-sig"))
            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["runner_requirement"], "NAVEAX")
            self.assertEqual(receipt["variables"]["PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT"], str(endpoint.resolve()))
            self.assertEqual(receipt["variables"]["PSMATRIX_FULL_MATRIX_HOME"], str(home.resolve()))
            self.assertFalse(receipt["secret_values_present"])
            self.assertTrue(all(row["exists"] for row in receipt["path_checks"]))

    def test_bootstrap_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bootstrap-") as temporary:
            root = Path(temporary) / "full-matrix"
            output = Path(temporary) / "receipt.json"
            first = self._run(root, output)
            second = self._run(root, output)
            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8-sig"))["status"], "PASS")

    def test_markers_bind_paths_to_final_version_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-bootstrap-") as temporary:
            root = Path(temporary) / "full-matrix"
            output = Path(temporary) / "receipt.json"
            completed = self._run(root, output)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            for child in ("endpoint-root", "home"):
                marker = json.loads((root / child / ".psmatrix-production-ga-path.json").read_text(encoding="utf-8-sig"))
                self.assertEqual(marker["kind"], "psmatrix.production-ga-full-matrix-local-path-marker")
                self.assertEqual(marker["version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()
