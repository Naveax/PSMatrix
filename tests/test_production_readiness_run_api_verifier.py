from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_readiness_run.py"
spec = importlib.util.spec_from_file_location("readiness_run_verifier", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HEAD = "a" * 40
REF = "final/2.0.0-production-control-plane-publication-anchor"


class ProductionReadinessRunAPIVerifierTests(unittest.TestCase):
    def _run(self, conclusion="success"):
        return {"id": 42, "name": module.EXPECTED_WORKFLOW, "event": "workflow_dispatch", "status": "completed", "conclusion": conclusion, "head_sha": HEAD, "head_branch": REF}

    def _artifacts(self):
        return [{"id": 99, "name": module.EXPECTED_ARTIFACT, "expired": False}]

    def test_successful_readiness_run_is_provenance_verified(self):
        value = module.verify_records(42, HEAD, REF, self._run(), self._artifacts())
        self.assertTrue(value["readiness_pass_observed"])
        self.assertFalse(value["summary_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_failed_readiness_run_is_still_valid_provenance_but_not_pass(self):
        value = module.verify_records(42, HEAD, REF, self._run("failure"), self._artifacts())
        self.assertFalse(value["readiness_pass_observed"])

    def test_wrong_ref_or_duplicate_artifact_fails_closed(self):
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(42, HEAD, "wrong-ref", self._run(), self._artifacts())
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(42, HEAD, REF, self._run(), self._artifacts() * 2)


if __name__ == "__main__":
    unittest.main()
