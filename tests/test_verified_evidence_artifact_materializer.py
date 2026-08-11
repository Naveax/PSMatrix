from __future__ import annotations

import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "materialize_verified_evidence_artifact.py"
spec = importlib.util.spec_from_file_location("artifact_materializer", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HEAD = "a" * 40


def api_verification():
    gates = []
    for index in range(11):
        gate = "validation-summary" if index == 0 else f"gate-{index}"
        gates.append({"gate": gate, "run_id": 100 + index, "workflow": f"workflow-{index}", "artifact": f"artifact-{index}", "artifact_id": 200 + index, "authority": "ci", "verified": True})
    return {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "execution_head": HEAD, "verified_gate_count": 11, "gates": gates}


class VerifiedEvidenceArtifactMaterializerTests(unittest.TestCase):
    def test_api_verified_artifact_safe_extract_produces_origin_receipt(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-artifact-materializer-") as temporary:
            root = Path(temporary)
            archive = root / "artifact.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr("nested/evidence.json", b"{}\n")
                bundle.writestr("status.txt", b"PASS\n")
            destination = root / "out"
            value = module.materialize(api_verification(), "validation-summary", archive, destination)
            self.assertEqual(value["run_id"], 100)
            self.assertEqual(value["artifact_id"], 200)
            self.assertEqual(value["file_count"], 2)
            self.assertTrue(value["path_traversal_rejected"])
            self.assertTrue(value["symlinks_rejected"])
            self.assertFalse(value["content_semantics_verified"])
            self.assertFalse(value["ga_eligible"])
            self.assertTrue((destination / "nested" / "evidence.json").is_file())

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-artifact-materializer-") as temporary:
            root = Path(temporary)
            archive = root / "artifact.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.txt", b"no\n")
            with self.assertRaises(module.EvidenceArtifactMaterializationError):
                module.safe_extract(archive, root / "out")
            self.assertFalse((root / "escape.txt").exists())

    def test_symlink_entry_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-artifact-materializer-") as temporary:
            root = Path(temporary)
            archive = root / "artifact.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(info, "target")
            with self.assertRaises(module.EvidenceArtifactMaterializationError):
                module.safe_extract(archive, root / "out")

    def test_unverified_gate_row_is_rejected_before_materialization(self):
        value = api_verification()
        value["gates"][0]["verified"] = False
        with tempfile.TemporaryDirectory(prefix="psmatrix-artifact-materializer-") as temporary:
            root = Path(temporary)
            archive = root / "artifact.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("x", b"x")
            with self.assertRaises(module.EvidenceArtifactMaterializationError):
                module.materialize(value, "validation-summary", archive, root / "out")


if __name__ == "__main__":
    unittest.main()
