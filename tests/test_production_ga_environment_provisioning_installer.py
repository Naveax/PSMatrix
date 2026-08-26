from __future__ import annotations

import json
import os
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

    def _single_release_material_map(self, root: Path, source: Path) -> Path:
        path = root / "material-map.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "kind": "psmatrix.production-ga-environment-material-map",
                    "version": "2.0.0",
                    "environments": {
                        "production-ga-release-signing": {
                            "secrets": {"PSMATRIX_RELEASE_PRIVATE_KEY": str(source)},
                            "vars": {},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

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

    def _run(self, material_map: Path, *extra: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT),
                "-MaterialMap", str(material_map), "-Contract", str(CONTRACT), "-DryRun", *extra,
            ],
            cwd=cwd,
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

    def test_repository_override_is_rejected_before_material_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-repo-pin-") as temporary:
            completed = self._run(self._material_map(Path(temporary)), "-Repository", "attacker/example")
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("repository must be exactly Naveax/PSMatrix", completed.stdout)
            self.assertNotIn("provisioned=", completed.stdout)

    def test_repo_root_is_script_anchored_not_current_working_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-nonrepo-cwd-") as temporary:
            external = Path(temporary)
            material_map = self._material_map(external)
            completed = self._run(material_map, cwd=external)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("environments=12 checks=41", completed.stdout)

    def test_duplicate_material_map_key_is_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-duplicate-json-") as temporary:
            root = Path(temporary)
            secret = root / "secret.txt"
            secret.write_text("fixture\n", encoding="utf-8")
            material_map = root / "material-map.json"
            material_map.write_text(
                "{"
                '"schema":1,"schema":1,'
                '"kind":"psmatrix.production-ga-environment-material-map",'
                '"version":"2.0.0",'
                '"environments":{"production-ga-release-signing":'
                '{"secrets":{"PSMATRIX_RELEASE_PRIVATE_KEY":' + json.dumps(str(secret)) + '},"vars":{}}}'
                "}",
                encoding="utf-8",
            )
            completed = self._run(material_map, "-Environment", "production-ga-release-signing")
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("duplicate JSON object key", completed.stdout)

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

    def test_external_parent_symlink_or_junction_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-material-link-") as temporary:
            external = Path(temporary)
            target_dir = Path(tempfile.mkdtemp(prefix=".tmp-provisioning-link-target-", dir=ROOT))
            alias = external / "linked-material"
            alias_kind = ""
            try:
                secret = target_dir / "release-private-key.pem"
                secret.write_text("not-a-real-secret", encoding="utf-8")
                alias_kind = self._create_directory_alias(alias, target_dir)
                material_map = self._single_release_material_map(external, alias / secret.name)
                completed = self._run(material_map, "-Environment", "production-ga-release-signing")
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
            finally:
                if alias_kind == "symlink" and (alias.exists() or alias.is_symlink()):
                    alias.unlink()
                elif alias_kind == "junction" and alias.exists():
                    alias.rmdir()
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_external_hardlink_alias_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-env-material-hardlink-") as temporary:
            external = Path(temporary)
            target = ROOT / ".tmp-provisioning-hardlink-target.pem"
            alias = external / "release-private-key.pem"
            try:
                target.write_text("not-a-real-secret", encoding="utf-8")
                try:
                    os.link(target, alias)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                material_map = self._single_release_material_map(external, alias)
                completed = self._run(material_map, "-Environment", "production-ga-release-signing")
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
            finally:
                alias.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_source_freezes_command_and_staging_boundary(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "Join-Path $PSScriptRoot '../..'",
            "Production GA provisioning repository must be exactly Naveax/PSMatrix",
            "GhPath must match the gh application resolved by the trusted operator PATH",
            "command output was intentionally redacted",
            "Copy-MaterialToStage",
            "Get-FileHash",
            "psmatrix-ga-provisioning-",
            "Assert-UniqueJsonKeys",
            "-RedirectStandardInput $InputFile",
            "'secret'",
            "'variable'",
            "'--env'",
            "'--repo'",
            "$ExpectedRepository",
            "[IO.FileAttributes]::ReparsePoint",
            "Properties['LinkType']",
        ):
            self.assertIn(required, source)
        self.assertNotIn("'--body'", source)
        self.assertNotIn("Write-Host $item.path", source)
        self.assertNotIn("$errorText", source)
        self.assertNotIn("Get-Content -Raw -LiteralPath $stderr", source)
        self.assertNotIn("$repoRoot = (Get-Location).Path", source)


if __name__ == "__main__":
    unittest.main()
