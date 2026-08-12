from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "complete_verified_final_evidence_run_ledger.py"

spec = importlib.util.spec_from_file_location("complete_verified_final_evidence_run_ledger_boundaries", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompleteVerifiedFinalEvidenceRunLedgerBoundaryTests(unittest.TestCase):
    def test_completion_scope_is_frozen_to_production_repository_and_execution_head(self) -> None:
        self.assertEqual(module.EXPECTED_REPOSITORY, "Naveax/PSMatrix")
        self.assertEqual(
            module.EXPECTED_EXECUTION_HEAD,
            "3ffc6b6d7cd58d64224f780aa819b50f50f72491",
        )
        self.assertEqual(module.SEEDED_GATES, ("validation-summary", "signed-release"))
        self.assertEqual(module.PER_PAGE, 100)


if __name__ == "__main__":
    unittest.main()
