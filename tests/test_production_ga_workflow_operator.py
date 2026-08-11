from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"Invoke-ProductionGAWorkflow.ps1"
BOOTSTRAP=ROOT/"ga-packs"/"03-authoritative-windows"/"final-production-bootstrap-contract.json"
READINESS_CONTRACT=ROOT/"ga-packs"/"03-authoritative-windows"/"final-production-readiness-contract.json"

class ProductionGAWorkflowOperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.pwsh=shutil.which("pwsh")
        if cls.pwsh is None: raise unittest.SkipTest("PowerShell 7 required")

    def _summary(self,root:Path,passed:bool)->Path:
        path=root/"readiness.json"; value={"schema":1,"kind":"psmatrix.production-readiness-summary","version":"2.0.0","status":"PASS" if passed else "FAIL","environment_count":12,"environment_passed":12 if passed else 0,"environment_failed":0 if passed else 12,"environment_readiness":passed,"secret_values_observed":False,"secret_hashes_observed":False,"secret_lengths_observed":False,"production_evidence_runs_complete":False,"final_ga_evaluator_invoked":False,"ga_eligible":False}; path.write_text(json.dumps(value),encoding="utf-8"); return path

    def _inputs(self,root:Path,value:dict)->Path:
        path=root/"inputs.json"; path.write_text(json.dumps(value),encoding="utf-8"); return path

    def _run(self,*args:str)->subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.pwsh),"-NoLogo","-NoProfile","-File",str(SCRIPT),*args,"-BootstrapContract",str(BOOTSTRAP),"-ReadinessContract",str(READINESS_CONTRACT),"-DryRun"],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30,check=False)

    def test_readiness_mode_allows_only_exact_readiness_workflow_without_inputs(self)->None:
        ok=self._run("-Mode","readiness","-Workflow",".github/workflows/ga-final-production-readiness.yml")
        self.assertEqual(ok.returncode,0,ok.stdout); self.assertIn("production_ga_workflow_operator=PASS mode=readiness",ok.stdout); self.assertIn("production_ga_workflow_dispatched=false",ok.stdout)
        bad=self._run("-Mode","readiness","-Workflow",".github/workflows/ga-final-full-runtime-matrix.yml")
        self.assertNotEqual(bad.returncode,0); self.assertIn("readiness mode may dispatch only",bad.stdout)

    def test_post_readiness_rejects_realistic_zero_of_twelve_fail_summary(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workflow-operator-") as temporary:
            root=Path(temporary); summary=self._summary(root,False)
            result=self._run("-Mode","post-readiness","-Workflow",".github/workflows/ga-final-full-runtime-matrix.yml","-ReadinessSummary",str(summary))
            self.assertNotEqual(result.returncode,0); self.assertIn("requires a real 12/12 PASS readiness summary",result.stdout)

    def test_post_readiness_pass_summary_builds_only_allowlisted_control_inputs_and_hides_values(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workflow-operator-") as temporary:
            root=Path(temporary); summary=self._summary(root,True); inputs=self._inputs(root,{"release_signing_run_id":314159265})
            result=self._run("-Mode","post-readiness","-Workflow",".github/workflows/ga-final-full-runtime-matrix.yml","-ReadinessSummary",str(summary),"-InputsJson",str(inputs))
            self.assertEqual(result.returncode,0,result.stdout); self.assertIn("workflow_input_names=release_signing_run_id",result.stdout); self.assertNotIn("314159265",result.stdout); self.assertIn("workflow_input_values_logged=false",result.stdout); self.assertIn("environment_secret_values_passed_as_inputs=false",result.stdout)

    def test_environment_secret_name_is_never_accepted_as_workflow_input(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workflow-operator-") as temporary:
            root=Path(temporary); summary=self._summary(root,True); inputs=self._inputs(root,{"PSMATRIX_GA_CI_PRIVATE_KEY":"not-a-real-key"})
            result=self._run("-Mode","post-readiness","-Workflow",".github/workflows/ga-final-full-runtime-matrix.yml","-ReadinessSummary",str(summary),"-InputsJson",str(inputs))
            self.assertNotEqual(result.returncode,0); self.assertIn("must never be passed as workflow input",result.stdout); self.assertNotIn("not-a-real-key",result.stdout)

    def test_non_allowlisted_workflow_and_moving_ref_are_rejected(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-workflow-operator-") as temporary:
            summary=self._summary(Path(temporary),True)
            result=self._run("-Mode","post-readiness","-Workflow",".github/workflows/ci.yml","-ReadinessSummary",str(summary))
            self.assertNotEqual(result.returncode,0); self.assertIn("not in the exact 19-path",result.stdout)
            result=self._run("-Mode","post-readiness","-Workflow",".github/workflows/ga-final-full-runtime-matrix.yml","-ReadinessSummary",str(summary),"-Ref","main")
            self.assertNotEqual(result.returncode,0); self.assertIn("frozen to final/2.0.0-production-control-plane-publication-anchor",result.stdout)

if __name__=="__main__": unittest.main()
