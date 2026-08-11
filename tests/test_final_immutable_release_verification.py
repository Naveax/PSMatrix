from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_immutable_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_immutable_release_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalImmutableReleaseVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.execution_head = "a" * 40
        self.release_commit = "b" * 40
        self.closure = {
            "schema": 1,
            "kind": "psmatrix.release-closure-readiness",
            "version": "2.0.0",
            "status": "READY_FOR_RELEASE_CLOSURE",
            "execution_head": self.execution_head,
            "precondition_count": 5,
            "preconditions_passed": 5,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_closed": False,
        }
        self.contract = {
            "schema": 1,
            "kind": "psmatrix.final-production-readiness-contract",
            "version": "2.0.0",
            "final_release_commit": self.release_commit,
        }
        self.settings = {"enabled": True}
        self.release = {"id": 77, "tag_name": "v2.0.0", "draft": False, "prerelease": False, "immutable": True, "published_at": "2026-08-11T12:00:00Z"}
        self.lightweight_ref = {"ref": "refs/tags/v2.0.0", "object": {"type": "commit", "sha": self.release_commit}}

    def test_immutable_release_with_exact_lightweight_tag_target_passes(self) -> None:
        value = self.module.verify(self.closure, self.contract, self.settings, self.release, self.lightweight_ref)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["tagged_commit"], self.release_commit)
        self.assertEqual(value["release_execution_control_head"], self.execution_head)
        self.assertTrue(value["repository_immutable_releases_enabled"])
        self.assertTrue(value["release_object_immutable"])
        self.assertTrue(value["final_immutable_ga_anchor_created"])
        self.assertFalse(value["release_closed"])

    def test_annotated_tag_must_resolve_directly_to_frozen_release_commit(self) -> None:
        tag_object_sha = "c" * 40
        ref = {"ref": "refs/tags/v2.0.0", "object": {"type": "tag", "sha": tag_object_sha}}
        annotated = {"sha": tag_object_sha, "object": {"type": "commit", "sha": self.release_commit}}
        value = self.module.verify(self.closure, self.contract, self.settings, self.release, ref, annotated)
        self.assertEqual(value["tagged_commit"], self.release_commit)

    def test_disabled_repository_immutability_fails_closed(self) -> None:
        self.settings["enabled"] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.module.verify(self.closure, self.contract, self.settings, self.release, self.lightweight_ref)

    def test_mutable_release_object_fails_closed(self) -> None:
        self.release["immutable"] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.module.verify(self.closure, self.contract, self.settings, self.release, self.lightweight_ref)

    def test_tag_targeting_execution_control_head_instead_of_release_commit_fails(self) -> None:
        self.lightweight_ref["object"]["sha"] = self.execution_head
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.module.verify(self.closure, self.contract, self.settings, self.release, self.lightweight_ref)

    def test_source_queries_immutable_settings_release_and_tag_ref(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("immutable-releases", text)
        self.assertIn("releases/tags/", text)
        self.assertIn("git/ref/tags/", text)
        self.assertIn("final_release_commit", text)
        self.assertIn("release_object_immutable", text)
        self.assertIn("final_immutable_ga_anchor_created", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
