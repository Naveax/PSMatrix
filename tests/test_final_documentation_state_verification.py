from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_documentation_state.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_documentation_state_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalDocumentationStateVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.repository_head = "c" * 40
        self.release = {
            "schema": 1,
            "kind": "psmatrix.final-immutable-release-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "tag": "v2.0.0",
            "release_id": 77,
            "release_execution_control_head": "a" * 40,
            "frozen_final_release_commit": "b" * 40,
            "publication_operation_verified": True,
            "publication_asset_count": 8,
            "release_asset_set_verified": True,
            "github_release_attestation_verified": True,
            "release_tag_created": True,
            "release_published": True,
            "final_immutable_ga_anchor_created": True,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_closed": False,
        }
        self.record = {
            "schema": 1,
            "kind": "psmatrix.final-2.0.0-documentation-state",
            "version": "2.0.0",
            "status": "FINAL_GA_DOCUMENTATION_COMPLETE",
            "release_tag": "v2.0.0",
            "release_id": 77,
            "final_release_commit": "b" * 40,
            "execution_control_head": "a" * 40,
            "documentation_repository_head": self.repository_head,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_immutable": True,
            "known_open_ga_blockers": [],
            "rc_or_prerelease_language_present": False,
            "placeholder_release_state_present": False,
            "secret_values_in_documentation": False,
            "secret_hashes_in_documentation": False,
            "secret_lengths_in_documentation": False,
            "documentation_source_sha256": "d" * 64,
            "document_count": 2,
            "documents": [
                {"path": "README.md", "sha256": "e" * 64, "size": 100},
                {"path": "docs/RELEASE.md", "sha256": "f" * 64, "size": 200},
            ],
        }

    def test_exact_final_documentation_record_passes(self) -> None:
        value = self.module.verify(self.record, self.release, self.repository_head)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["document_count"], 2)
        self.assertTrue(value["immutable_publication_operation_verified"])
        self.assertEqual(value["immutable_publication_asset_count"], 8)
        self.assertTrue(value["immutable_release_asset_set_verified"])
        self.assertTrue(value["immutable_release_attestation_verified"])
        self.assertTrue(value["documentation_final_state_closed"])
        self.assertTrue(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_asset_unbound_or_repository_unbound_immutable_release_fails_closed(self) -> None:
        for field in (
            "publication_operation_verified",
            "release_asset_set_verified",
            "github_release_attestation_verified",
        ):
            with self.subTest(field=field):
                original = self.release[field]
                self.release[field] = False
                with self.assertRaises(self.module.FinalDocumentationStateError):
                    self.module.verify(self.record, self.release, self.repository_head)
                self.release[field] = original
        self.release["publication_asset_count"] = 7
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)
        self.release["publication_asset_count"] = 8
        self.release["repository"] = "someone-else/PSMatrix"
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)

    def test_prerelease_or_placeholder_state_fails_closed(self) -> None:
        self.record["rc_or_prerelease_language_present"] = True
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)
        self.record["rc_or_prerelease_language_present"] = False
        self.record["placeholder_release_state_present"] = True
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)

    def test_release_identity_or_repository_head_drift_fails(self) -> None:
        self.record["release_id"] = 88
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)
        self.record["release_id"] = 77
        self.record["documentation_repository_head"] = "0" * 40
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)

    def test_secret_observation_or_duplicate_document_fails_closed(self) -> None:
        self.record["secret_values_in_documentation"] = True
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)
        self.record["secret_values_in_documentation"] = False
        self.record["documents"][1]["path"] = "README.md"
        with self.assertRaises(self.module.FinalDocumentationStateError):
            self.module.verify(self.record, self.release, self.repository_head)

    def test_source_requires_machine_readable_final_state_without_closing_release(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("publication_operation_verified", text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("FINAL_GA_DOCUMENTATION_COMPLETE", text)
        self.assertIn("known_open_ga_blockers", text)
        self.assertIn("rc_or_prerelease_language_present", text)
        self.assertIn("placeholder_release_state_present", text)
        self.assertIn("documentation_final_state_closed", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
