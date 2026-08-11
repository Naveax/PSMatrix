from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "bind_verified_evidence_content.py"
spec = importlib.util.spec_from_file_location("content_binder", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def materialization(state, gate="validation-summary"):
    return {
        "schema": 1, "kind": "psmatrix.final-ga-evidence-artifact-materialization", "version": "2.0.0", "status": "PASS",
        "execution_head": HEAD, "gate": gate, "run_id": 101, "artifact": "artifact", "artifact_id": 202,
        "artifact_archive_sha256": "b" * 64, "file_count": state["file_count"], "tree_sha256": state["tree_sha256"], "files": state["files"],
        "content_semantics_verified": False, "ga_eligible": False,
    }


def semantic(gate="validation-summary"):
    kind = module.GATE_VERIFIERS[gate][1]
    return {"schema": 1, "kind": kind, "version": "2.0.0", "status": "PASS", "ga_eligible": False, "_receipt_sha256": "c" * 64}


class EvidenceContentReceiptBinderTests(unittest.TestCase):
    def test_exact_api_tree_and_semantic_receipt_bind(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-content-binder-") as temporary:
            root = Path(temporary)
            (root / "evidence.json").write_text("{}\n", encoding="utf-8")
            state = module.tree_state(root)
            value = module.bind(materialization(state), "validation-summary", state, state, semantic())
            self.assertEqual(value["run_id"], 101)
            self.assertEqual(value["artifact_id"], 202)
            self.assertTrue(value["api_artifact_origin_verified"])
            self.assertTrue(value["materialized_tree_verified"])
            self.assertTrue(value["content_semantics_verified"])
            self.assertFalse(value["ga_eligible"])

    def test_tree_drift_after_semantic_verification_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-content-binder-") as temporary:
            root = Path(temporary)
            path = root / "evidence.json"
            path.write_text("{}\n", encoding="utf-8")
            before = module.tree_state(root)
            path.write_text('{"changed":true}\n', encoding="utf-8")
            after = module.tree_state(root)
            with self.assertRaises(module.EvidenceContentBindingError):
                module.bind(materialization(before), "validation-summary", before, after, semantic())

    def test_materialization_tree_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-content-binder-") as temporary:
            root = Path(temporary)
            (root / "evidence.json").write_text("{}\n", encoding="utf-8")
            state = module.tree_state(root)
            receipt = materialization(state)
            receipt["tree_sha256"] = "d" * 64
            with self.assertRaises(module.EvidenceContentBindingError):
                module.bind(receipt, "validation-summary", state, state, semantic())

    def test_semantic_receipt_kind_drift_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-content-binder-") as temporary:
            root = Path(temporary)
            (root / "evidence.json").write_text("{}\n", encoding="utf-8")
            state = module.tree_state(root)
            wrong = semantic()
            wrong["kind"] = "psmatrix.wrong"
            with self.assertRaises(module.EvidenceContentBindingError):
                module.bind(materialization(state), "validation-summary", state, state, wrong)

    def test_public_auth_requires_separate_cross_gate_binder(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-content-binder-") as temporary:
            root = Path(temporary)
            (root / "evidence.json").write_text("{}\n", encoding="utf-8")
            state = module.tree_state(root)
            with self.assertRaises(module.EvidenceContentBindingError):
                module.validate_semantic_receipt("public-oauth", {"schema": 1})


if __name__ == "__main__":
    unittest.main()
