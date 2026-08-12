from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_validation_control_plane.py"
HEAD = "06c80421ecb8c6668e5e4334f9138a55ae56e1fd"

spec = importlib.util.spec_from_file_location("final_validation_control_plane_pagination", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationControlPlanePaginationTests(unittest.TestCase):
    def _run(self, run_id: int, name: str, path: str) -> dict:
        return {
            "id": run_id,
            "name": name,
            "path": path,
            "event": "push",
            "head_branch": "main",
            "head_sha": HEAD,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": "Naveax/PSMatrix"},
        }

    def test_partial_protected_run_listing_is_rejected(self) -> None:
        ci = self._run(1, "ci", ".github/workflows/ci.yml")
        source = self._run(
            2,
            "verification-hardening-source-certification",
            ".github/workflows/verification-hardening-source-certification.yml",
        )
        private = self._run(
            3,
            "production-ga-repository-private-material-scan",
            ".github/workflows/ga-repository-private-material-scan.yml",
        )
        partial = {"total_count": 2, "workflow_runs": []}
        empty_validation = {"total_count": 0, "workflow_runs": []}
        with self.assertRaises(module.FinalValidationControlPlaneError):
            module.verify(
                control_head=HEAD,
                ci_run=ci,
                source_certification_run=source,
                private_material_scan_run=private,
                final_release_signing_runs=partial,
                final_validation_summary_runs=empty_validation,
            )


if __name__ == "__main__":
    unittest.main()
