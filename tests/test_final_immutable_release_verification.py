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
        self.publication_contract = {
            "schema": 1,
            "kind": "psmatrix.final-immutable-release-publication-contract",
            "version": "2.0.0",
            "repository": "Naveax/PSMatrix",
            "release": {
                "tag": "v2.0.0",
                "name": "PSMatrix 2.0.0",
                "target_commit": self.release_commit,
                "immutable_releases_required": True,
                "draft_before_asset_upload": True,
                "prerelease": False,
            },
            "publication_asset_count": 8,
            "publication_assets": [
                {"role": role, "name": name, "digest_source": source}
                for role, (name, source) in self.module.EXPECTED_ASSETS.items()
            ],
        }
        self.operation_assets = []
        for index, (role, (name, _source)) in enumerate(self.module.EXPECTED_ASSETS.items(), start=1):
            digest = f"{index:064x}"
            self.operation_assets.append(
                {
                    "role": role,
                    "name": name,
                    "path": f"/external/{name}",
                    "size": 100 + index,
                    "sha256": digest,
                    "github_digest": f"sha256:{digest}",
                }
            )
        self.publication_operation = {
            "schema": 1,
            "kind": "psmatrix.final-immutable-release-publication-operation",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "tag": "v2.0.0",
            "release_name": "PSMatrix 2.0.0",
            "target_commit": self.release_commit,
            "release_execution_control_head": self.execution_head,
            "publication_asset_count": 8,
            "publication_assets": self.operation_assets,
            "current_protected_bundle_reverified": True,
            "mutation_executed": True,
            "immutable_releases_enabled": True,
            "draft_asset_set_verified": True,
            "published_asset_set_verified": True,
            "release_tag_exact_commit_verified": True,
            "release_published": True,
            "release_immutable": True,
            "release_id": 77,
            "release_closed": False,
        }
        self.settings = {"enabled": True}
        self.release = {
            "id": 77,
            "tag_name": "v2.0.0",
            "name": "PSMatrix 2.0.0",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "published_at": "2026-08-11T12:00:00Z",
            "assets": [
                {
                    "name": row["name"],
                    "state": "uploaded",
                    "size": row["size"],
                    "digest": row["github_digest"],
                }
                for row in self.operation_assets
            ],
        }
        self.lightweight_ref = {
            "ref": "refs/tags/v2.0.0",
            "object": {"type": "commit", "sha": self.release_commit},
        }

    def verify(self, *, attestation: bool = True):
        return self.module.verify(
            self.closure,
            self.contract,
            self.publication_contract,
            self.publication_operation,
            self.settings,
            self.release,
            self.lightweight_ref,
            attestation,
        )

    def test_immutable_release_with_exact_assets_and_attestation_passes(self) -> None:
        value = self.verify()
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["tagged_commit"], self.release_commit)
        self.assertEqual(value["release_execution_control_head"], self.execution_head)
        self.assertEqual(value["publication_asset_count"], 8)
        self.assertTrue(value["publication_operation_verified"])
        self.assertTrue(value["release_asset_set_verified"])
        self.assertTrue(value["github_release_attestation_verified"])
        self.assertTrue(value["repository_immutable_releases_enabled"])
        self.assertTrue(value["release_object_immutable"])
        self.assertTrue(value["final_immutable_ga_anchor_created"])
        self.assertFalse(value["release_closed"])

    def test_annotated_tag_must_resolve_directly_to_frozen_release_commit(self) -> None:
        tag_object_sha = "c" * 40
        ref = {"ref": "refs/tags/v2.0.0", "object": {"type": "tag", "sha": tag_object_sha}}
        annotated = {"sha": tag_object_sha, "object": {"type": "commit", "sha": self.release_commit}}
        value = self.module.verify(
            self.closure,
            self.contract,
            self.publication_contract,
            self.publication_operation,
            self.settings,
            self.release,
            ref,
            True,
            annotated,
        )
        self.assertEqual(value["tagged_commit"], self.release_commit)

    def test_disabled_repository_immutability_fails_closed(self) -> None:
        self.settings["enabled"] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_mutable_release_object_fails_closed(self) -> None:
        self.release["immutable"] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_tag_targeting_execution_control_head_instead_of_release_commit_fails(self) -> None:
        self.lightweight_ref["object"]["sha"] = self.execution_head
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_missing_or_extra_release_asset_fails_closed(self) -> None:
        self.release["assets"] = list(self.release["assets"][:-1])
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.release["assets"] = list(self.release["assets"]) + [
            {"name": "unexpected.bin", "state": "uploaded", "size": 1, "digest": "sha256:" + "f" * 64}
        ]
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_single_remote_asset_digest_or_size_drift_fails_closed(self) -> None:
        self.release["assets"][0] = dict(self.release["assets"][0])
        self.release["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.release["assets"][0] = dict(self.release["assets"][0])
        self.release["assets"][0]["size"] += 1
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_publication_operation_must_bind_same_release_id_head_and_target(self) -> None:
        self.publication_operation["release_id"] = 78
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.publication_operation["release_execution_control_head"] = "d" * 40
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.publication_operation["target_commit"] = "e" * 40
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_publication_operation_requires_fresh_bundle_and_both_asset_checks(self) -> None:
        for field in (
            "current_protected_bundle_reverified",
            "draft_asset_set_verified",
            "published_asset_set_verified",
            "release_tag_exact_commit_verified",
            "release_published",
            "release_immutable",
        ):
            with self.subTest(field=field):
                original = self.publication_operation[field]
                self.publication_operation[field] = False
                with self.assertRaises(self.module.FinalImmutableReleaseError):
                    self.verify()
                self.publication_operation[field] = original

    def test_github_release_attestation_must_be_verified(self) -> None:
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify(attestation=False)

    def test_publication_contract_asset_name_or_target_drift_fails_closed(self) -> None:
        self.publication_contract["publication_assets"][0] = dict(self.publication_contract["publication_assets"][0])
        self.publication_contract["publication_assets"][0]["name"] = "wrong.whl"
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.publication_contract["release"]["target_commit"] = "f" * 40
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_source_queries_current_api_and_cryptographically_verifies_release_attestation(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('API_VERSION = "2026-03-10"', text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("immutable-releases", text)
        self.assertIn("releases/tags/", text)
        self.assertIn("git/ref/tags/", text)
        self.assertIn('"release", "verify"', text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("publication_operation_verified", text)
        self.assertIn("final_immutable_ga_anchor_created", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
