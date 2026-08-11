from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_immutable_anchor.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_ga_anchor_target_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAAnchorTargetVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.head = "a" * 40
        self.closure = {
            "schema": 1,
            "kind": "psmatrix.release-closure-readiness",
            "version": "2.0.0",
            "status": "READY_FOR_RELEASE_CLOSURE",
            "execution_head": self.head,
            "precondition_count": 5,
            "preconditions_passed": 5,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "final_immutable_ga_anchor_created": False,
            "release_closed": False,
        }
        self.ref = {"ref": "refs/heads/final/2.0.0-ga-publication-anchor", "object": {"type": "commit", "sha": self.head}}

    def test_exact_anchor_target_passes_without_overclaiming_immutability(self) -> None:
        value = self.module.verify(self.closure, self.ref)
        self.assertEqual(value["status"], "PASS")
        self.assertTrue(value["final_ga_anchor_target_verified"])
        self.assertTrue(value["exact_commit_target_verified"])
        self.assertFalse(value["immutability_enforcement_verified"])
        self.assertFalse(value["final_immutable_ga_anchor_created"])
        self.assertTrue(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_wrong_commit_target_fails_closed(self) -> None:
        self.ref["object"]["sha"] = "b" * 40
        with self.assertRaises(self.module.FinalGAAnchorTargetError):
            self.module.verify(self.closure, self.ref)

    def test_wrong_anchor_name_is_rejected(self) -> None:
        with self.assertRaises(self.module.FinalGAAnchorTargetError):
            self.module.verify(self.closure, self.ref, "final/not-authoritative")

    def test_pre_anchor_release_receipt_is_required(self) -> None:
        self.closure["final_immutable_ga_anchor_created"] = True
        with self.assertRaises(self.module.FinalGAAnchorTargetError):
            self.module.verify(self.closure, self.ref)

    def test_source_uses_github_ref_api_but_keeps_immutability_unverified(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("git/ref/heads/", text)
        self.assertIn("final/2.0.0-ga-publication-anchor", text)
        self.assertIn("exact_commit_target_verified", text)
        self.assertIn("immutability_enforcement_verified", text)
        self.assertIn('"final_immutable_ga_anchor_created": False', text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
