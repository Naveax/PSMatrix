from __future__ import annotations

import importlib.util
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_evidence_content_closure_receipt.py"


def load_module():
    spec = importlib.util.spec_from_file_location("content_closure_receipt_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def closure() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": "a" * 40,
        "required_gate_count": 11,
        "api_verified_gate_count": 11,
        "content_verified_gate_count": 11,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


class FinalEvidenceContentClosureReceiptVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.expected = closure()
        self.module._load_builder = lambda: types.SimpleNamespace(build=lambda api, contract, bindings, public: dict(self.expected))
        self.bindings = [{"gate": f"g{index}"} for index in range(9)]

    def test_exact_rederived_closure_passes(self) -> None:
        value = self.module.verify({}, {}, self.bindings, {}, dict(self.expected))
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["verified_gate_count"], 11)
        self.assertEqual(value["source_binding_receipt_count"], 10)
        self.assertTrue(value["closure_exactly_recomputed"])
        self.assertEqual(len(value["closure_canonical_sha256"]), 64)
        self.assertFalse(value["ga_eligible"])

    def test_tampered_closure_fails_closed(self) -> None:
        supplied = dict(self.expected)
        supplied["execution_head"] = "b" * 40
        with self.assertRaises(self.module.EvidenceContentClosureReceiptVerificationError):
            self.module.verify({}, {}, self.bindings, {}, supplied)

    def test_exact_nine_single_bindings_are_required(self) -> None:
        with self.assertRaises(self.module.EvidenceContentClosureReceiptVerificationError):
            self.module.verify({}, {}, self.bindings[:-1], {}, dict(self.expected))

    def test_evaluator_or_ga_boundary_drift_fails(self) -> None:
        expected = dict(self.expected)
        expected["ga_eligible"] = True
        self.module._load_builder = lambda: types.SimpleNamespace(build=lambda api, contract, bindings, public: dict(expected))
        with self.assertRaises(self.module.EvidenceContentClosureReceiptVerificationError):
            self.module.verify({}, {}, self.bindings, {}, dict(expected))

    def test_source_uses_repository_owned_builder_and_canonical_digest(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_final_evidence_content_closure.py", text)
        self.assertIn("closure_exactly_recomputed", text)
        self.assertIn("closure_canonical_sha256", text)
        self.assertIn("source_binding_receipt_count", text)
        self.assertIn("ga_eligible", text)


if __name__ == "__main__":
    unittest.main()
