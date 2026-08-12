from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_ga_evaluator_dispatch_plan.py"

spec = importlib.util.spec_from_file_location("final_ga_evaluator_dispatch_plan_boundaries", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalGAEvaluatorDispatchPlanBoundaryTests(unittest.TestCase):
    def test_frozen_production_dispatch_boundaries_do_not_drift(self) -> None:
        self.assertEqual(module.EXPECTED_REPOSITORY, "Naveax/PSMatrix")
        self.assertEqual(
            module.EXPECTED_EXECUTION_REF,
            "final/2.0.0-production-control-plane-publication-anchor",
        )
        self.assertEqual(
            module.EXPECTED_EXECUTION_HEAD,
            "3ffc6b6d7cd58d64224f780aa819b50f50f72491",
        )
        self.assertEqual(module.EXPECTED_WORKFLOW, "production-ga-final-evaluator")
        self.assertEqual(module.EXPECTED_WORKFLOW_PATH, ".github/workflows/ga-final-evaluator.yml")
        self.assertEqual(
            module.INPUT_BY_GATE,
            {
                "validation-summary": "validation_run_id",
                "signed-release": "release_signing_run_id",
                "authoritative-windows": "windows_rebind_run_id",
                "complete-runtime-matrix": "full_matrix_run_id",
                "public-oauth": "oauth_run_id",
                "public-mtls": "mtls_run_id",
                "external-otlp": "otlp_run_id",
                "key-rotation": "key_rotation_run_id",
                "disaster-recovery": "recovery_run_id",
                "security-review": "security_review_run_id",
                "vulnerability-scan": "vulnerability_scan_run_id",
            },
        )


if __name__ == "__main__":
    unittest.main()
