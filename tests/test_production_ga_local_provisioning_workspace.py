from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Initialize-ProductionGAProvisioningWorkspace.ps1"


class ProductionGALocalProvisioningWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest("PowerShell 7 required")

    def _run(self, root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.pwsh), "-NoLogo", "-NoProfile", "-File", str(SCRIPT), "-Root", str(root), *extra],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
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

    def test_workspace_generates_real_authorities_full_matrix_paths_and_nineteen_check_fragments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace = Path(temporary) / "workspace"
            completed = self._run(workspace)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("locally_prepared_checks=19/41", completed.stdout)
            self.assertIn("github_environment_mutation_executed=false", completed.stdout)
            summary = json.loads((workspace / "local-provisioning-summary.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(summary["locally_prepared_check_count"], 19)
            self.assertEqual(summary["remaining_external_or_review_check_count"], 22)
            self.assertFalse(summary["safety"]["production_readiness_claimed"])
            self.assertFalse(summary["safety"]["ga_eligible"])
            authority = json.loads(Path(summary["fragments"]["signing_authorities"]).read_text(encoding="utf-8"))
            matrix = json.loads(Path(summary["fragments"]["full_matrix"]).read_text(encoding="utf-8"))
            self.assertEqual(authority["check_count"], 17)
            self.assertEqual(matrix["check_count"], 2)
            self.assertEqual(len(list((workspace / "authorities").glob("*.private.pem"))), 9)
            self.assertTrue((workspace / "full-matrix-runtime" / "endpoint-root").is_dir())
            self.assertTrue((workspace / "full-matrix-runtime" / "home").is_dir())

    def test_default_rerun_refuses_silent_authority_rotation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace = Path(temporary) / "workspace"
            first = self._run(workspace)
            second = self._run(workspace)
            self.assertEqual(first.returncode, 0, first.stdout)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to overwrite an existing signing key", second.stdout.lower())

    def test_explicit_force_can_rebuild_workspace_but_never_claim_readiness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace = Path(temporary) / "workspace"
            self.assertEqual(self._run(workspace).returncode, 0)
            forced = self._run(workspace, "-ForceAuthorities")
            self.assertEqual(forced.returncode, 0, forced.stdout)
            summary = json.loads((workspace / "local-provisioning-summary.json").read_text(encoding="utf-8-sig"))
            self.assertFalse(summary["safety"]["production_readiness_claimed"])
            self.assertFalse(summary["safety"]["github_environment_mutation_executed"])

    def test_repo_local_workspace_is_rejected_before_private_material_creation(self) -> None:
        forbidden = ROOT / ".tmp-production-ga-workspace"
        try:
            completed = self._run(forbidden)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("must stay outside the repository", completed.stdout)
            self.assertFalse(forbidden.exists())
        finally:
            if forbidden.exists():
                shutil.rmtree(forbidden)

    def test_external_workspace_symlink_or_junction_to_repository_is_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-link-") as temporary:
            external = Path(temporary)
            target = ROOT / ".tmp-production-ga-workspace-link-target"
            alias = external / "workspace"
            kind = ""
            try:
                target.mkdir()
                kind = self._create_directory_alias(alias, target)
                completed = self._run(alias)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertEqual(list(target.iterdir()), [])
            finally:
                self._remove_directory_alias(alias, kind)
                if target.exists():
                    shutil.rmtree(target)

    def test_existing_authority_root_symlink_or_junction_is_rejected_before_key_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-authority-root-link-") as temporary:
            external = Path(temporary)
            workspace = external / "workspace"
            target = external / "authority-target"
            alias = workspace / "authorities"
            kind = ""
            workspace.mkdir()
            target.mkdir()
            try:
                kind = self._create_directory_alias(alias, target)
                completed = self._run(workspace)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertEqual(list(target.iterdir()), [])
                self.assertFalse((workspace / "fragments").exists())
            finally:
                self._remove_directory_alias(alias, kind)

    def test_hardlinked_fragment_output_is_rejected_before_key_generation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-fragment-hardlink-") as temporary:
            external = Path(temporary)
            workspace = external / "workspace"
            fragment_root = workspace / "fragments"
            fragment_root.mkdir(parents=True)
            target = ROOT / ".tmp-production-ga-authority-fragment-target.json"
            alias = fragment_root / "signing-authorities.material-map.json"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    os.link(target, alias)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                completed = self._run(workspace)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertFalse((workspace / "authorities").exists())
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
            finally:
                alias.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_hardlinked_summary_alias_is_rejected_before_workspace_creation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-summary-hardlink-") as temporary:
            external = Path(temporary)
            workspace = external / "workspace"
            target = ROOT / ".tmp-production-ga-summary-hardlink-target.json"
            alias = external / "summary.json"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    os.link(target, alias)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                completed = self._run(workspace, "-SummaryOutput", str(alias))
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("must not contain links or reparse points", completed.stdout)
                self.assertFalse(workspace.exists())
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
            finally:
                alias.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_source_preflights_workspace_summary_and_child_outputs_before_generation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        workspace_guard = "$workspace = Assert-OutsideRepository $Root 'Production GA provisioning workspace path'"
        outside_reparse_guard = "$full = Assert-NoExistingLinkOrReparseComponents $Path $Label"
        summary_guard = "Assert-NoExistingLinkOrReparseComponents $summaryPath"
        first_workspace_create = "New-Item -ItemType Directory -Path $workspace -Force"
        authority_generation = "provision_production_ga_authorities.py"
        self.assertIn(workspace_guard, source)
        self.assertIn(outside_reparse_guard, source)
        self.assertIn(summary_guard, source)
        self.assertLess(source.index(workspace_guard), source.index(first_workspace_create))
        self.assertLess(source.index(outside_reparse_guard), source.index(first_workspace_create))
        self.assertLess(source.index(summary_guard), source.index(first_workspace_create))
        for token in (
            "$authorityRoot,",
            "$fullMatrixRoot,",
            "$authorityFragment,",
            "$fullMatrixFragment,",
            "$fullMatrixReceipt",
        ):
            self.assertIn(token, source)
            self.assertLess(source.index(token), source.index(authority_generation))
        self.assertIn("[IO.FileAttributes]::ReparsePoint", source)
        self.assertIn("Properties['LinkType']", source)


if __name__ == "__main__":
    unittest.main()
