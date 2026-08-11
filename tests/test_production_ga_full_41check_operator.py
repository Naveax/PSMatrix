from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-ProductionGAFullFortyOneCheckProvisioning.ps1"


class ProductionGAFullFortyOneCheckOperatorTests(unittest.TestCase):
    def test_source_freezes_exact_five_fragment_forty_one_check_flow(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "Initialize-ProductionGAProvisioningWorkspace.ps1",
            "build_public_auth_material_map_fragment.py",
            "build_otlp_material_map_fragment.py",
            "build_security_review_material_map_fragment.py",
            "merge_production_ga_material_map_fragments.py",
            "select_missing_production_ga_material.py",
            "Invoke-ProductionGAEnvironmentProvisioning.ps1",
            "verify_production_ga_provisioning_receipt.py",
        ):
            self.assertIn(required, text)
        self.assertIn("local_check_count = 19", text)
        self.assertIn("external_or_review_check_count = 22", text)
        self.assertIn("total_material_check_count = 41", text)
        self.assertIn("fragment_count = 5", text)
        self.assertIn("@initializeArgs", text)
        self.assertIn("@provisionArgs", text)
        self.assertIn("AllowPartialEnvironment = $true", text)
        self.assertIn("production_readiness_verified = $false", text)
        self.assertIn("final_ga_evaluator_invoked = $false", text)
        self.assertIn("ga_eligible = $false", text)
        self.assertNotIn("--body", text)

    def test_repo_local_workspace_is_rejected_before_external_material_access(self) -> None:
        pwsh = shutil.which("pwsh")
        if not pwsh:
            self.skipTest("pwsh required")
        local_root = ROOT / ".tmp-full-41-operator-must-not-exist"
        completed = subprocess.run(
            [
                pwsh,
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT),
                "-Root",
                str(local_root),
                "-PublicAuthMaterialRoot",
                str(ROOT / "missing-public-auth"),
                "-OtlpEndpointFile",
                str(ROOT / "missing-otlp-endpoint"),
                "-OtlpHeadersFile",
                str(ROOT / "missing-otlp-headers"),
                "-SecurityReviewPacket",
                str(ROOT / "missing-review-packet"),
                "-SecurityReviewReport",
                str(ROOT / "missing-review-report"),
                "-DryRun",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("workspace must stay outside the repository", completed.stdout)
        self.assertFalse(local_root.exists())


if __name__ == "__main__":
    unittest.main()
