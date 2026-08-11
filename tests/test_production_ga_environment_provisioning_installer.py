from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-ProductionGAEnvironmentProvisioning.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


class ProductionGAEnvironmentProvisioningInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 is required")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _material_map(self, root: Path) -> Path:
        environments = {}
        for environment in self.contract["environments"]:
            secrets = {}
            variables = {}
            for source, target in (("required_secrets", secrets), ("required_vars", variables)):
                for name in environment[source]:
                    path = root / environment["name"] / f"{name}.txt"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"fixture-for-{name}\n", encoding="utf-8")
                    target[name] = str(path)
            environments[environment["name"]] = {"secrets": secrets, "vars": variables}
        path = root / "material-map.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "kind": "psmatrix.production-ga-environment-material-map",
                    "version": "2.0.0",
                    "environments": environments,
                }
            ),
            encoding="utf-8",
        )
        return path

    def _run(self, material_map: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT),
                "-MaterialMap", str(material_map), "-Contract", str(CONTRACT), "-DryRun", *extra,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )

    def test_dry_run_validates_exact_all_environment_material_by_file_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-material-") as temporary:
            completed = self._run(self._material_map(Path(temporary)))
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("production_ga_environment_provisioning_plan=PASS environments=12 checks=41", completed.stdout)
            self.assertIn("secret_values_logged=false", completed.stdout)
            self.assertIn("production_ga_environment_provisioning_executed=false", completed.stdout)

    def test_dry_run_can_validate_one_environment_without_requiring_other_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-material-") as temporary:
            material_map = self._material_map(Path(temporary))
            completed = self._run(material_map, "-Environment", "production-ga-release-signing")
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("environments=1 checks=1", completed.stdout)

    def test_material_sources_inside_repository_are_rejected(self) -> None:
        inside = ROOT / ".tmp-provisioning-value.txt"
        map_path = ROOT / ".tmp-provisioning-map.json"
        try:
            inside.write_text("not-a-real-secret", encoding="utf-8")
            map_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "psmatrix.production-ga-environment-material-map",
                        "version": "2.0.0",
                        "environments": {
                            "production-ga-release-signing": {
                                "secrets": {"PSMATRIX_RELEASE_PRIVATE_KEY": str(inside)},
                                "vars": {},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            completed = self._run(map_path, "-Environment", "production-ga-release-signing")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("must stay outside the repository", completed.stdout)
        finally:
            inside.unlink(missing_ok=True)
            map_path.unlink(missing_ok=True)

    def test_source_uses_stdin_redirection_and_never_body_argument(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("-RedirectStandardInput $InputFile", source)
        self.assertIn("'secret'", source)
        self.assertIn("'variable'", source)
        self.assertIn("'--env'", source)
        self.assertIn("'--repo'", source)
        self.assertNotIn("'--body'", source)
        self.assertNotIn('Write-Host $item.path', source)


if __name__ == "__main__":
    unittest.main()
