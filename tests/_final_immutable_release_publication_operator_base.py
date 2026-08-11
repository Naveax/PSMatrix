from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "publish_final_immutable_release.py"
CONTRACT = ROOT / "scripts" / "ga" / "final-immutable-release-publication-contract.json"


def load_module():
    spec = importlib.util.spec_from_file_location("final_immutable_release_publication", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FinalImmutableReleasePublicationOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.target = self.contract["release"]["target_commit"]
        self.closure = {
            "schema": 1,
            "kind": "psmatrix.release-closure-readiness",
            "version": "2.0.0",
            "status": "READY_FOR_RELEASE_CLOSURE",
            "execution_head": "a" * 40,
            "precondition_count": 5,
            "preconditions_passed": 5,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_closed": False,
        }
        self.protected = {
            "schema": 1,
            "kind": "psmatrix.protected-final-release-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 11,
            "execution_head": "b" * 40,
            "release_commit": self.target,
            "locked_artifact_count": 6,
            "verified_artifact_count": 6,
            "release_manifest_cryptographically_verified": True,
            "release_public_authority_bound_to_lock": True,
            "artifact_content_verified": True,
            "signed_release_verified": True,
            "final_windows_evidence_rebound": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }
        self.run_verification = {"schema": 1, "kind": "test-run-verification"}
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name).resolve()
        self.lock = self.bundle / "active-lock.json"
        self.lock.write_text("{}\n", encoding="utf-8")
        self.product_rows: list[dict[str, object]] = []
        for role, (name, source) in self.module.EXPECTED_ASSETS.items():
            if source != "signed_release_manifest":
                continue
            data = f"FINAL-ASSET-{role}\n".encode()
            (self.bundle / name).write_bytes(data)
            self.product_rows.append({"name": name, "sha256": sha(data), "size": len(data)})
        public_name = self.module.EXPECTED_ASSETS["release_public_key"][0]
        (self.bundle / public_name).write_bytes(b"PUBLIC-KEY\n")
        manifest_name = self.module.EXPECTED_ASSETS["signed_release_manifest"][0]
        payload = {
            "manifest": {
                "schema": 1,
                "kind": "psmatrix.release-manifest",
                "version": "2.0.0",
                "created_at": "1970-01-01T00:00:00+00:00",
                "artifacts": sorted(self.product_rows, key=lambda row: str(row["name"])),
            },
            "attestation": {"payloadType": "application/vnd.in-toto+json", "payload": "test", "signatures": []},
        }
        (self.bundle / manifest_name).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def plan(self):
        with patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)):
            return self.module.build_plan(
                self.contract,
                self.closure,
                self.protected,
                self.bundle,
                self.lock,
                self.run_verification,
            )

    def remote_assets(self, plan):
        return [
            {
                "name": row["name"],
                "state": "uploaded",
                "size": row["size"],
                "digest": row["github_digest"],
            }
            for row in plan["publication_assets"]
        ]

    def draft(self, plan):
        return {
            "databaseId": 77,
            "tagName": "v2.0.0",
            "name": "PSMatrix 2.0.0",
            "isPrerelease": False,
            "targetCommitish": plan["target_commit"],
            "isDraft": True,
            "isImmutable": False,
            "publishedAt": None,
        }

    def published(self, plan):
        value = self.draft(plan)
        value.update({"isDraft": False, "isImmutable": True, "publishedAt": "2026-08-11T00:00:00Z"})
        return value

    def test_dry_run_binds_exact_eight_assets_and_reverifies_current_bundle(self) -> None:
        value = self.plan()
        self.assertEqual(value["status"], "DRY_RUN")
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["target_commit"], self.target)
        self.assertEqual(value["publication_asset_count"], 8)
        self.assertTrue(value["current_protected_bundle_reverified"])
        self.assertFalse(value["mutation_executed"])
        self.assertFalse(value["release_published"])
        self.assertFalse(value["delete_or_clobber_existing_assets_allowed"])
        self.assertFalse(value["release_closed"])

    def test_fresh_protected_bundle_receipt_must_equal_supplied_receipt(self) -> None:
        fresh = dict(self.protected)
        fresh["run_id"] = 12

        class FakeVerifier:
            @staticmethod
            def verify(_bundle, _lock, _run):
                return fresh

        with (
            patch.object(self.module, "_load_protected_verifier", return_value=FakeVerifier()),
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module._reverify_current_bundle(self.protected, self.bundle, self.lock, self.run_verification)

    def test_signed_manifest_digest_mismatch_is_rejected(self) -> None:
        product = next(row for row in self.product_rows if str(row["name"]).endswith(".whl"))
        (self.bundle / str(product["name"])).write_bytes(b"tampered\n")
        with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
            self.plan()

    def test_wrong_protected_release_commit_is_rejected(self) -> None:
        self.protected["release_commit"] = "f" * 40
        with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
            self.plan()

    def test_contract_asset_drift_is_rejected(self) -> None:
        changed = json.loads(json.dumps(self.contract))
        changed["publication_assets"][0]["name"] = "wrong.whl"
        with (
            patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)),
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.build_plan(changed, self.closure, self.protected, self.bundle, self.lock, self.run_verification)

    def test_execute_uploads_without_clobber_and_verifies_before_publish(self) -> None:
        plan = self.plan()
        remote = self.remote_assets(plan)
        uploads: list[str] = []
        with (
            patch.object(self.module, "_remote_absent", side_effect=[True, True]),
            patch.object(self.module, "_immutable_enabled", return_value=False),
            patch.object(self.module, "_enable_immutable") as enable,
            patch.object(self.module, "_disable_immutable") as disable,
            patch.object(self.module, "_create_draft"),
            patch.object(self.module, "_view_release", side_effect=[self.draft(plan), self.published(plan)]),
            patch.object(self.module, "_upload_asset", side_effect=lambda _gh, path: uploads.append(Path(path).name)),
            patch.object(self.module, "_list_assets", side_effect=[remote, remote]),
            patch.object(self.module, "_publish") as publish,
            patch.object(self.module, "_verify_tag") as verify_tag,
            patch.object(self.module, "_rollback_pre_publish") as rollback,
        ):
            receipt = self.module.execute_plan(plan, "gh")
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["release_id"], 77)
        self.assertEqual(len(uploads), 8)
        self.assertEqual(set(uploads), {row["name"] for row in plan["publication_assets"]})
        enable.assert_called_once_with("gh")
        disable.assert_not_called()
        publish.assert_called_once()
        verify_tag.assert_called_once_with("gh", self.target)
        rollback.assert_not_called()
        self.assertFalse(receipt["immutable_releases_initially_enabled"])
        self.assertTrue(receipt["immutable_releases_changed_by_operation"])
        self.assertFalse(receipt["post_publish_reconciled_after_client_error"])
        self.assertTrue(receipt["release_published"])
        self.assertTrue(receipt["release_immutable"])
        self.assertFalse(receipt["release_closed"])

    def test_enable_failure_enters_prepublish_rollback(self) -> None:
        plan = self.plan()
        with (
            patch.object(self.module, "_remote_absent", side_effect=[True, True]),
            patch.object(self.module, "_immutable_enabled", return_value=False),
            patch.object(self.module, "_enable_immutable", side_effect=self.module.FinalImmutableReleasePublicationError("verification lost")),
            patch.object(self.module, "_create_draft") as create,
            patch.object(self.module, "_rollback_pre_publish") as rollback,
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.execute_plan(plan, "gh")
        create.assert_not_called()
        rollback.assert_called_once_with("gh", plan, draft_created=False, immutable_changed=True)

    def test_prepublish_failure_invokes_transactional_rollback(self) -> None:
        plan = self.plan()
        remote = self.remote_assets(plan)
        remote[0] = dict(remote[0])
        remote[0]["digest"] = "sha256:" + "0" * 64
        with (
            patch.object(self.module, "_remote_absent", side_effect=[True, True]),
            patch.object(self.module, "_immutable_enabled", return_value=False),
            patch.object(self.module, "_enable_immutable"),
            patch.object(self.module, "_create_draft"),
            patch.object(self.module, "_view_release", return_value=self.draft(plan)),
            patch.object(self.module, "_upload_asset"),
            patch.object(self.module, "_list_assets", return_value=remote),
            patch.object(self.module, "_publish") as publish,
            patch.object(self.module, "_rollback_pre_publish") as rollback,
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.execute_plan(plan, "gh")
        publish.assert_not_called()
        rollback.assert_called_once_with("gh", plan, draft_created=True, immutable_changed=True)

    def test_rollback_restores_immutable_setting_only_if_operation_changed_it(self) -> None:
        plan = self.plan()
        with (
            patch.object(self.module, "_rollback_draft") as draft_rollback,
            patch.object(self.module, "_immutable_enabled", return_value=True),
            patch.object(self.module, "_disable_immutable") as disable,
        ):
            self.module._rollback_pre_publish("gh", plan, draft_created=True, immutable_changed=True)
        draft_rollback.assert_called_once_with("gh", plan)
        disable.assert_called_once_with("gh")

        with (
            patch.object(self.module, "_rollback_draft") as draft_rollback,
            patch.object(self.module, "_immutable_enabled") as enabled,
            patch.object(self.module, "_disable_immutable") as disable,
        ):
            self.module._rollback_pre_publish("gh", plan, draft_created=True, immutable_changed=False)
        draft_rollback.assert_called_once_with("gh", plan)
        enabled.assert_not_called()
        disable.assert_not_called()

    def test_rollback_accepts_already_restored_immutable_setting(self) -> None:
        plan = self.plan()
        with (
            patch.object(self.module, "_rollback_draft"),
            patch.object(self.module, "_immutable_enabled", return_value=False),
            patch.object(self.module, "_disable_immutable") as disable,
        ):
            self.module._rollback_pre_publish("gh", plan, draft_created=True, immutable_changed=True)
        disable.assert_not_called()

    def test_ambiguous_unconfirmed_draft_is_never_deleted(self) -> None:
        plan = self.plan()
        with (
            patch.object(self.module, "_remote_absent", side_effect=[False, False]),
            patch.object(self.module, "_rollback_draft") as rollback,
            patch.object(self.module, "_disable_immutable") as disable,
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module._rollback_pre_publish("gh", plan, draft_created=False, immutable_changed=True)
        rollback.assert_not_called()
        disable.assert_not_called()

    def test_post_publish_client_error_reconciles_exact_remote_state(self) -> None:
        plan = self.plan()
        remote = self.remote_assets(plan)
        with (
            patch.object(self.module, "_remote_absent", side_effect=[True, True]),
            patch.object(self.module, "_immutable_enabled", return_value=True),
            patch.object(self.module, "_create_draft"),
            patch.object(self.module, "_view_release", return_value=self.draft(plan)),
            patch.object(self.module, "_upload_asset"),
            patch.object(self.module, "_list_assets", return_value=remote),
            patch.object(self.module, "_publish", side_effect=self.module.FinalImmutableReleasePublicationError("client lost response")),
            patch.object(self.module, "_verify_published_remote", return_value=None) as reconcile,
            patch.object(self.module, "_rollback_pre_publish") as rollback,
        ):
            receipt = self.module.execute_plan(plan, "gh")
        reconcile.assert_called_once_with("gh", plan, 77)
        rollback.assert_not_called()
        self.assertTrue(receipt["post_publish_reconciled_after_client_error"])
        self.assertTrue(receipt["release_published"])

    def test_post_publish_unverifiable_state_never_attempts_rollback(self) -> None:
        plan = self.plan()
        remote = self.remote_assets(plan)
        with (
            patch.object(self.module, "_remote_absent", side_effect=[True, True]),
            patch.object(self.module, "_immutable_enabled", return_value=True),
            patch.object(self.module, "_create_draft"),
            patch.object(self.module, "_view_release", return_value=self.draft(plan)),
            patch.object(self.module, "_upload_asset"),
            patch.object(self.module, "_list_assets", return_value=remote),
            patch.object(self.module, "_publish", side_effect=self.module.FinalImmutableReleasePublicationError("publish uncertain")),
            patch.object(self.module, "_verify_published_remote", side_effect=self.module.FinalImmutableReleasePublicationError("remote not published")),
            patch.object(self.module, "_rollback_pre_publish") as rollback,
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.execute_plan(plan, "gh")
        rollback.assert_not_called()

    def test_preexisting_release_blocks_before_setting_or_mutation(self) -> None:
        plan = self.plan()
        with (
            patch.object(self.module, "_remote_absent", return_value=False),
            patch.object(self.module, "_immutable_enabled") as immutable,
            patch.object(self.module, "_create_draft") as create,
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.execute_plan(plan, "gh")
        immutable.assert_not_called()
        create.assert_not_called()

    def test_source_forbids_clobber_and_freezes_current_api_repository_and_contract(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('API_VERSION = "2026-03-10"', text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("final-immutable-release-publication-contract.json", text)
        self.assertIn("verify_protected_final_release_bundle.py", text)
        self.assertIn("immutable-releases", text)
        self.assertIn('method="DELETE"', text)
        self.assertIn("--draft=false", text)
        self.assertIn("_verify_remote_assets", text)
        self.assertIn("_rollback_pre_publish", text)
        self.assertIn("_verify_published_remote", text)
        self.assertNotIn("--clobber", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
