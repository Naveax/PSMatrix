from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"ga"/"Invoke-ProductionGAEnvironmentProvisioning.ps1"
CONTRACT=ROOT/"ga-packs"/"03-authoritative-windows"/"final-production-readiness-contract.json"

class PartialProductionGAEnvironmentProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls)->None:
        cls.pwsh=shutil.which("pwsh")
        if cls.pwsh is None: raise unittest.SkipTest("PowerShell 7 required")

    def _map(self,root:Path,include_report:bool=False)->Path:
        secrets={}
        for name in ("PSMATRIX_GA_SECURITY_REVIEW_PRIVATE_KEY","PSMATRIX_GA_SECURITY_REVIEW_PUBLIC_KEY"):
            path=root/f"{name}.txt"; path.write_text(f"fixture-{name}\n",encoding="utf-8"); secrets[name]=str(path)
        variables={}
        if include_report:
            report=root/"PSMATRIX_GA_SECURITY_REVIEW_REPORT_JSON.txt"; report.write_text('{"status":"PASS"}\n',encoding="utf-8"); variables["PSMATRIX_GA_SECURITY_REVIEW_REPORT_JSON"]=str(report)
        path=root/"map.json"; path.write_text(json.dumps({"schema":1,"kind":"psmatrix.production-ga-environment-material-map","version":"2.0.0","environments":{"production-ga-security-review-signing":{"secrets":secrets,"vars":variables}}}),encoding="utf-8"); return path

    def _run(self,map_path:Path,*extra:str)->subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.pwsh),"-NoLogo","-NoProfile","-File",str(SCRIPT),"-MaterialMap",str(map_path),"-Contract",str(CONTRACT),"-Environment","production-ga-security-review-signing","-DryRun",*extra],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30,check=False)

    def test_default_strict_mode_rejects_partial_security_review_environment(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-env-") as temporary:
            result=self._run(self._map(Path(temporary)))
            self.assertNotEqual(result.returncode,0); self.assertIn("missing variable source",result.stdout)

    def test_explicit_partial_mode_accepts_two_declared_signing_secrets_only(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-env-") as temporary:
            result=self._run(self._map(Path(temporary)),"-AllowPartialEnvironment")
            self.assertEqual(result.returncode,0,result.stdout); self.assertIn("environments=1 checks=2",result.stdout); self.assertIn("partial_environment_mode=true",result.stdout); self.assertIn("secret_values_logged=false",result.stdout)

    def test_partial_mode_requires_explicit_environment_selection(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-env-") as temporary:
            result=subprocess.run([str(self.pwsh),"-NoLogo","-NoProfile","-File",str(SCRIPT),"-MaterialMap",str(self._map(Path(temporary))),"-Contract",str(CONTRACT),"-AllowPartialEnvironment","-DryRun"],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30,check=False)
            self.assertNotEqual(result.returncode,0); self.assertIn("requires one or more explicit -Environment",result.stdout)

    def test_partial_mode_still_rejects_undeclared_names(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-env-") as temporary:
            root=Path(temporary); map_path=self._map(root); value=json.loads(map_path.read_text(encoding="utf-8")); rogue=root/"ROGUE.txt"; rogue.write_text("rogue\n",encoding="utf-8"); value["environments"]["production-ga-security-review-signing"]["secrets"]["ROGUE_SECRET"]=str(rogue); map_path.write_text(json.dumps(value),encoding="utf-8")
            result=self._run(map_path,"-AllowPartialEnvironment")
            self.assertNotEqual(result.returncode,0); self.assertIn("undeclared secret/var names",result.stdout)

    def test_complete_map_still_passes_strict_mode(self)->None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-env-") as temporary:
            result=self._run(self._map(Path(temporary),include_report=True))
            self.assertEqual(result.returncode,0,result.stdout); self.assertIn("environments=1 checks=3",result.stdout); self.assertIn("partial_environment_mode=false",result.stdout)

if __name__=="__main__": unittest.main()
