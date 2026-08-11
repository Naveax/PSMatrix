from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "bind_public_auth_evidence_content.py"
spec = importlib.util.spec_from_file_location("public_auth_binder", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
HEAD = "a" * 40


def materialization(gate, state, run_id, artifact_id):
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-artifact-materialization", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "gate": gate, "run_id": run_id, "artifact": f"artifact-{gate}", "artifact_id": artifact_id, "file_count": state["file_count"], "tree_sha256": state["tree_sha256"], "files": state["files"], "content_semantics_verified": False, "ga_eligible": False}


def semantic():
    return {"schema": 1, "kind": "psmatrix.public-auth-cross-gate-bundle-verification", "version": "2.0.0", "status": "PASS", "same_live_report_sha256": True, "different_public_endpoints": True, "same_deployment_authority": True, "same_release_manifest_sha256": True, "same_release_wheel_sha256": True, "oauth_proof_verified": True, "mtls_proof_verified": True, "ga_eligible": False, "_receipt_sha256": "c" * 64}


class PublicAuthContentBinderTests(unittest.TestCase):
    def test_two_distinct_api_artifacts_bind_to_cross_gate_semantics(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-binder-") as temporary:
            root = Path(temporary)
            oauth = root / "oauth"; mtls = root / "mtls"; oauth.mkdir(); mtls.mkdir()
            (oauth / "evidence.json").write_text('{"gate":"oauth"}\n', encoding="utf-8")
            (mtls / "evidence.json").write_text('{"gate":"mtls"}\n', encoding="utf-8")
            oauth_state = module.tree_state(oauth); mtls_state = module.tree_state(mtls)
            value = module.bind(materialization("public-oauth", oauth_state, 101, 201), materialization("public-mtls", mtls_state, 102, 202), oauth_state, oauth_state, mtls_state, mtls_state, semantic())
            self.assertEqual(value["covered_gates"], ["public-oauth", "public-mtls"])
            self.assertTrue(value["api_artifact_origin_verified"])
            self.assertTrue(value["content_semantics_verified"])
            self.assertTrue(value["cross_gate_semantics_verified"])
            self.assertFalse(value["ga_eligible"])

    def test_same_run_identity_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-binder-") as temporary:
            root = Path(temporary)
            oauth = root / "oauth"; mtls = root / "mtls"; oauth.mkdir(); mtls.mkdir()
            (oauth / "x").write_text("a", encoding="utf-8"); (mtls / "x").write_text("b", encoding="utf-8")
            os = module.tree_state(oauth); ms = module.tree_state(mtls)
            with self.assertRaises(module.PublicAuthContentBindingError):
                module.bind(materialization("public-oauth", os, 101, 201), materialization("public-mtls", ms, 101, 202), os, os, ms, ms, semantic())

    def test_tree_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-binder-") as temporary:
            root = Path(temporary)
            oauth = root / "oauth"; mtls = root / "mtls"; oauth.mkdir(); mtls.mkdir()
            path = oauth / "x"; path.write_text("a", encoding="utf-8"); (mtls / "x").write_text("b", encoding="utf-8")
            os = module.tree_state(oauth); ms = module.tree_state(mtls)
            path.write_text("changed", encoding="utf-8")
            with self.assertRaises(module.PublicAuthContentBindingError):
                module.bind(materialization("public-oauth", os, 101, 201), materialization("public-mtls", ms, 102, 202), os, module.tree_state(oauth), ms, ms, semantic())

    def test_semantic_cross_gate_flag_failure_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-binder-") as temporary:
            root = Path(temporary)
            oauth = root / "oauth"; mtls = root / "mtls"; oauth.mkdir(); mtls.mkdir()
            (oauth / "x").write_text("a", encoding="utf-8"); (mtls / "x").write_text("b", encoding="utf-8")
            os = module.tree_state(oauth); ms = module.tree_state(mtls)
            sem = semantic(); sem["same_deployment_authority"] = False
            with self.assertRaises(module.PublicAuthContentBindingError):
                module.bind(materialization("public-oauth", os, 101, 201), materialization("public-mtls", ms, 102, 202), os, os, ms, ms, sem)


if __name__ == "__main__":
    unittest.main()
