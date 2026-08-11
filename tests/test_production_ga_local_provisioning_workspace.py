from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"Initialize-ProductionGAProvisioningWorkspace.ps1"

class ProductionGALocalProvisioningWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.pwsh=shutil.which("pwsh")
        if cls.pwsh is None: raise unittest.SkipTest("PowerShell 7 required")

    def _run(self,root:Path,*extra:str)->subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.pwsh),"-NoLogo","-NoProfile","-File",str(SCRIPT),"-Root",str(root),*extra],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90,check=False)

    def test_workspace_generates_real_authorities_full_matrix_paths_and_nineteen_check_fragments(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace=Path(temporary)/"workspace"; completed=self._run(workspace)
            self.assertEqual(completed.returncode,0,completed.stdout); self.assertIn("locally_prepared_checks=19/41",completed.stdout); self.assertIn("github_environment_mutation_executed=false",completed.stdout)
            summary=json.loads((workspace/"local-provisioning-summary.json").read_text(encoding="utf-8-sig")); self.assertEqual(summary["locally_prepared_check_count"],19); self.assertEqual(summary["remaining_external_or_review_check_count"],22); self.assertFalse(summary["safety"]["production_readiness_claimed"]); self.assertFalse(summary["safety"]["ga_eligible"])
            authority=json.loads(Path(summary["fragments"]["signing_authorities"]).read_text(encoding="utf-8")); matrix=json.loads(Path(summary["fragments"]["full_matrix"]).read_text(encoding="utf-8")); self.assertEqual(authority["check_count"],17); self.assertEqual(matrix["check_count"],2)
            self.assertEqual(len(list((workspace/"authorities").glob("*.private.pem"))),9); self.assertTrue((workspace/"full-matrix-runtime"/"endpoint-root").is_dir()); self.assertTrue((workspace/"full-matrix-runtime"/"home").is_dir())

    def test_default_rerun_refuses_silent_authority_rotation(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace=Path(temporary)/"workspace"; first=self._run(workspace); second=self._run(workspace)
            self.assertEqual(first.returncode,0,first.stdout); self.assertNotEqual(second.returncode,0); self.assertIn("refusing to overwrite an existing signing key",second.stdout.lower())

    def test_explicit_force_can_rebuild_workspace_but_never_claim_readiness(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-local-ga-workspace-") as temporary:
            workspace=Path(temporary)/"workspace"; self.assertEqual(self._run(workspace).returncode,0); forced=self._run(workspace,"-ForceAuthorities")
            self.assertEqual(forced.returncode,0,forced.stdout); summary=json.loads((workspace/"local-provisioning-summary.json").read_text(encoding="utf-8-sig")); self.assertFalse(summary["safety"]["production_readiness_claimed"]); self.assertFalse(summary["safety"]["github_environment_mutation_executed"])

    def test_repo_local_workspace_is_rejected_before_private_material_creation(self)->None:
        forbidden=ROOT/".tmp-production-ga-workspace"
        try:
            completed=self._run(forbidden); self.assertNotEqual(completed.returncode,0); self.assertIn("must stay outside the repository",completed.stdout); self.assertFalse(forbidden.exists())
        finally:
            if forbidden.exists(): shutil.rmtree(forbidden)

if __name__=="__main__": unittest.main()
