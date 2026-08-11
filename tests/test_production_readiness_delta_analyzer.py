from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "analyze_production_readiness_delta.py"


def load():
    spec = importlib.util.spec_from_file_location("readiness_delta", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class ProductionReadinessDeltaAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()

    def _readiness(self, passed: int = 0) -> dict:
        return {"schema":1,"kind":"psmatrix.production-readiness-summary","version":"2.0.0","status":"PASS" if passed==12 else "FAIL","environment_count":12,"environment_passed":passed,"environment_failed":12-passed}

    def _inventory(self, present: int) -> dict:
        names=[f"env-{i}" for i in range(12)]
        complete=12 if present==41 else 0
        return {"schema":1,"kind":"psmatrix.production-ga-environment-inventory-audit","version":"2.0.0","environment_count":12,"required_check_count":41,"present_check_count":present,"missing_check_count":41-present,"environments":[{"environment":name,"status":"PASS" if i<complete else "FAIL"} for i,name in enumerate(names)]}

    def test_zero_of_forty_one_reports_no_false_readiness(self) -> None:
        value=self.module.analyze(self._readiness(),self._inventory(0))
        self.assertEqual(value["current_name_inventory_present"],0)
        self.assertFalse(value["eligible_for_readiness_rerun"])
        self.assertFalse(value["environment_readiness_claimed"])
        self.assertFalse(value["ga_eligible"])

    def test_partial_names_show_progress_but_do_not_qualify_rerun(self) -> None:
        value=self.module.analyze(self._readiness(),self._inventory(17))
        self.assertEqual(value["current_name_inventory_present"],17)
        self.assertEqual(value["current_name_inventory_missing"],24)
        self.assertFalse(value["eligible_for_readiness_rerun"])

    def test_forty_one_names_only_qualifies_rerun_not_readiness(self) -> None:
        value=self.module.analyze(self._readiness(),self._inventory(41))
        self.assertTrue(value["eligible_for_readiness_rerun"])
        self.assertEqual(value["current_name_complete_environments"],12)
        self.assertFalse(value["environment_readiness_claimed"])
        self.assertFalse(value["production_evidence_claimed"])
        self.assertFalse(value["final_ga_evaluator_invoked"])
        self.assertFalse(value["ga_eligible"])

    def test_invalid_inventory_cardinality_fails_closed(self) -> None:
        inventory=self._inventory(41); inventory["required_check_count"]=40
        with self.assertRaises(self.module.ReadinessDeltaError):
            self.module.analyze(self._readiness(),inventory)

if __name__=="__main__": unittest.main()
