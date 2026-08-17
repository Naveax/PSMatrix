from __future__ import annotations

import json
import os
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

    def _create_directory_alias(self, alias: Path, target: Path) -> str:
        try:
            alias.symlink_to(target, target_is_directory=True)
            return "symlink"
        except (NotImplementedError, OSError):
            pass
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
                check=False,
            )
            if completed.returncode == 0:
                return "junction"
        self.skipTest("directory symlink/junction creation is unavailable on this platform")

    def _remove_directory_alias(self, alias: Path, kind: str) -> None:
        if kind == "symlink" and (alias.exists() or alias.is_symlink()):
            alias.unlink()
        elif kind == "junction" and alias.exists():
            alias.rmdir()

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
            endpoint_receipt = Path(receipt["variables"]["PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT"])
            home_receipt = Path(receipt["variables"]["PSMATRIX_FULL_MATRIX_HOME"])
            self.assertTrue(endpoint_receipt.samefile(endpoint))
            self.assertTrue(home_receipt.samefile(home))
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

    def test_external_root_symlink_or_junction_to_repository_is_rejected_before_marker_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-link-") as temporary:
            external = Path(temporary)
            target = ROOT / ".tmp-production-ga-full-matrix-link-target"
            alias = external / "full-matrix"
            output = external / "receipt.json"
            kind = ""
            try:
                target.mkdir()
                kind = self._create_directory_alias(alias, target)
                completed = self._run(alias, output)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertEqual(list(target.iterdir()), [])
                self.assertFalse(output.exists())
            finally:
                self._remove_directory_alias(alias, kind)
                if target.exists():
                    shutil.rmtree(target)

    def test_hardlinked_receipt_alias_is_rejected_before_runtime_root_creation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-receipt-hardlink-") as temporary:
            external = Path(temporary)
            root = external / "full-matrix"
            target = ROOT / ".tmp-production-ga-full-matrix-receipt-target.json"
            output = external / "receipt.json"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    os.link(target, output)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                completed = self._run(root, output)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertFalse(root.exists())
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
            finally:
                output.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_hardlinked_marker_alias_is_rejected_without_target_mutation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-full-matrix-marker-hardlink-") as temporary:
            external = Path(temporary)
            root = external / "full-matrix"
            output = external / "receipt.json"
            endpoint = root / "endpoint-root"
            home = root / "home"
            endpoint.mkdir(parents=True)
            home.mkdir(parents=True)
            target = ROOT / ".tmp-production-ga-full-matrix-marker-target.json"
            marker = endpoint / ".psmatrix-production-ga-path.json"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    os.link(target, marker)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                completed = self._run(root, output)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
                self.assertFalse(output.exists())
            finally:
                marker.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_source_guards_root_receipt_runtime_directories_and_markers(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("rootPath = Assert-NoExistingLinkOrReparseComponents", source)
        self.assertIn("Assert-NoExistingLinkOrReparseComponents $Output", source)
        self.assertIn("Assert-NoExistingLinkOrReparseComponents $path 'Production GA full-matrix runtime path'", source)
        self.assertIn("Assert-NoExistingLinkOrReparseComponents $markerPath", source)
        self.assertIn("[System.IO.FileAttributes]::ReparsePoint", source)
        self.assertIn("Properties['LinkType']", source)


if __name__ == "__main__":
    unittest.main()
