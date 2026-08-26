from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Initialize-ProductionGAProvisioningWorkspace.ps1"


class ProductionGAWorkspaceCommandBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 required")

    def _run(self, workspace: Path, *, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.pwsh, "-NoLogo", "-NoProfile", "-File", str(SCRIPT), "-Root", str(workspace)],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )

    def test_initializer_is_repository_anchored_and_uses_trusted_absolute_sources(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "Join-Path $PSScriptRoot '../..'",
            "Get-Command python -CommandType Application -All",
            "$commandPath = [string]$command.Path",
            "Assert-TrustedApplicationPath $commandPath 'Trusted python executable' 'python.exe'",
            "[Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)",
            "Join-Path $localApplicationData 'Microsoft\\WindowsApps'",
            "Test-PathEqual $parent $windowsAppsRoot",
            "Windows application alias name mismatch",
            "Trusted python executable must stay outside the repository",
            "Join-Path $repoRoot 'scripts/ga/provision_production_ga_authorities.py'",
            "Join-Path $repoRoot 'scripts/ga/build_authority_material_map_fragment.py'",
            "Join-Path $repoRoot 'scripts/ga/Initialize-ProductionGAFullMatrixPaths.ps1'",
            "Join-Path $repoRoot 'scripts/ga/build_full_matrix_material_map_fragment.py'",
            "Assert-UniqueJsonKeys",
        ):
            self.assertIn(required, source)
        self.assertNotIn("(Get-Location).Path", source)
        self.assertNotIn("$command.Source", source)
        self.assertNotIn("$item.FullName", source)
        self.assertNotIn("if ($IsWindows) { return }", source)
        self.assertNotIn("signing_authority_fragment=", source)
        self.assertNotIn("full_matrix_fragment=", source)
        self.assertNotIn("summary=$summaryPath", source)

    def test_exact_repository_root_is_rejected_from_nonrepo_cwd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workspace-boundary-cwd-") as temporary:
            completed = self._run(ROOT, cwd=Path(temporary))
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("must stay outside the repository", completed.stdout)

    def test_external_workspace_succeeds_from_nonrepo_cwd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workspace-boundary-") as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            cwd = root / "cwd"
            cwd.mkdir()
            completed = self._run(workspace, cwd=cwd)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertTrue((workspace / "local-provisioning-summary.json").is_file())
            self.assertEqual(len(list((workspace / "authorities").glob("*.private.pem"))), 9)


if __name__ == "__main__":
    unittest.main()
