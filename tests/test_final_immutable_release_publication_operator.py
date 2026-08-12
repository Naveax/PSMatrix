from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_BASE_PATH = Path(__file__).with_name(
    "_final_immutable_release_publication_operator_base.py"
)


def _load_base():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_immutable_release_publication_operator_test_base",
        _BASE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load immutable publication operator test base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_base = _load_base()


class FinalImmutableReleasePublicationOperatorTests(
    _base.FinalImmutableReleasePublicationOperatorTests
):
    def setUp(self) -> None:
        super().setUp()
        self.attestation_temp = tempfile.TemporaryDirectory()
        self.attestation_bundle_root = Path(self.attestation_temp.name)
        self.attestation_asset = self.attestation_bundle_root / "psmatrix-2.0.0-final-ga-attestation.zip"
        self.attestation_asset.write_bytes(b"CANONICAL-FINAL-GA-ATTESTATION-ZIP\n")
        digest = hashlib.sha256(self.attestation_asset.read_bytes()).hexdigest()
        self.attestation_operation = {"status": "PASS"}
        self.attestation_public_asset_receipt = {"status": "PASS"}
        self.attestation_verification = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-public-release-asset-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": self.closure["execution_head"],
            "asset_name": self.attestation_asset.name,
            "asset_path": str(self.attestation_asset),
            "asset_size": self.attestation_asset.stat().st_size,
            "asset_sha256": digest,
            "github_digest": f"sha256:{digest}",
            "current_bundle_matches_verified_operation": True,
            "current_asset_matches_producer_receipt": True,
            "zip_members_match_current_verified_bundle": True,
            "private_key_material_absent": True,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "release_closed": False,
        }

    def tearDown(self) -> None:
        self.attestation_temp.cleanup()
        super().tearDown()

    def plan(self):
        with (
            patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)),
            patch.object(
                self.module,
                "_reverify_final_ga_attestation_public_asset",
                return_value=dict(self.attestation_verification),
            ),
        ):
            return self.module.build_plan(
                self.contract,
                self.closure,
                self.protected,
                self.bundle,
                self.lock,
                self.run_verification,
                self.attestation_operation,
                self.attestation_public_asset_receipt,
                self.attestation_bundle_root,
                self.attestation_verification,
            )

    def test_dry_run_binds_exact_eight_assets_and_reverifies_current_bundle(self) -> None:
        value = self.plan()
        self.assertEqual(value["status"], "DRY_RUN")
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["target_commit"], self.target)
        self.assertEqual(value["publication_asset_count"], 9)
        self.assertEqual(len(value["publication_assets"]), 9)
        self.assertEqual(value["publication_assets"][-1]["name"], "psmatrix-2.0.0-final-ga-attestation.zip")
        self.assertTrue(value["current_protected_bundle_reverified"])
        self.assertTrue(value["current_final_ga_attestation_public_asset_reverified"])
        self.assertTrue(value["final_ga_attestation_public_asset_execution_head_verified"])
        self.assertFalse(value["mutation_executed"])
        self.assertFalse(value["release_published"])
        self.assertFalse(value["delete_or_clobber_existing_assets_allowed"])
        self.assertFalse(value["release_closed"])

    def test_contract_asset_drift_is_rejected(self) -> None:
        import json

        changed = json.loads(json.dumps(self.contract))
        changed["publication_assets"][0]["name"] = "wrong.whl"
        with (
            patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)),
            patch.object(
                self.module,
                "_reverify_final_ga_attestation_public_asset",
                return_value=dict(self.attestation_verification),
            ),
            self.assertRaises(self.module.FinalImmutableReleasePublicationError),
        ):
            self.module.build_plan(
                changed,
                self.closure,
                self.protected,
                self.bundle,
                self.lock,
                self.run_verification,
                self.attestation_operation,
                self.attestation_public_asset_receipt,
                self.attestation_bundle_root,
                self.attestation_verification,
            )

    def test_attestation_asset_execution_head_mismatch_is_rejected_before_mutation(self) -> None:
        self.attestation_verification["execution_head"] = "f" * 40
        with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
            self.plan()

    def test_attestation_asset_byte_drift_is_rejected_before_mutation(self) -> None:
        self.attestation_asset.write_bytes(b"TAMPERED\n")
        with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
            self.plan()

    def test_self_consistent_forged_pass_receipt_is_rejected_by_canonical_reverification(self) -> None:
        with (
            patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)),
            self.assertRaisesRegex(
                self.module.FinalImmutableReleasePublicationError,
                "canonical reverification failed",
            ),
        ):
            self.module.build_plan(
                self.contract,
                self.closure,
                self.protected,
                self.bundle,
                self.lock,
                self.run_verification,
                self.attestation_operation,
                self.attestation_public_asset_receipt,
                self.attestation_bundle_root,
                self.attestation_verification,
            )

    def test_attestation_verification_receipt_must_equal_current_canonical_result(self) -> None:
        canonical = dict(self.attestation_verification)
        supplied = dict(canonical)
        supplied["member_count"] = 999
        with (
            patch.object(self.module, "_reverify_current_bundle", return_value=dict(self.protected)),
            patch.object(
                self.module,
                "_reverify_final_ga_attestation_public_asset",
                return_value=canonical,
            ),
            self.assertRaisesRegex(
                self.module.FinalImmutableReleasePublicationError,
                "differs from current canonical reverification",
            ),
        ):
            self.module.build_plan(
                self.contract,
                self.closure,
                self.protected,
                self.bundle,
                self.lock,
                self.run_verification,
                self.attestation_operation,
                self.attestation_public_asset_receipt,
                self.attestation_bundle_root,
                supplied,
            )

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
        self.assertEqual(len(uploads), 9)
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

    def test_source_forbids_clobber_and_freezes_current_api_repository_and_contract(self) -> None:
        public = _base.SCRIPT
        impl = public.with_name("_publish_final_immutable_release_impl.py")
        extension = public.with_name("_publish_final_immutable_release_nine_asset.py")
        verifier = public.with_name("verify_final_ga_attestation_public_asset.py")
        text = (
            public.read_text(encoding="utf-8")
            + "\n"
            + impl.read_text(encoding="utf-8")
            + "\n"
            + extension.read_text(encoding="utf-8")
            + "\n"
            + verifier.read_text(encoding="utf-8")
        )
        self.assertIn('API_VERSION = "2026-03-10"', text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("final-immutable-release-publication-contract.json", text)
        self.assertIn("verify_protected_final_release_bundle.py", text)
        self.assertIn("verify_final_ga_attestation_public_asset.py", text)
        self.assertIn("final-attestation-operation", text)
        self.assertIn("final-attestation-public-asset-receipt", text)
        self.assertIn("final-attestation-bundle-root", text)
        self.assertIn("final-attestation-public-asset-verification", text)
        self.assertIn("_reverify_final_ga_attestation_public_asset", text)
        self.assertIn("psmatrix-2.0.0-final-ga-attestation.zip", text)
        self.assertIn("immutable-releases", text)
        self.assertIn('method="DELETE"', text)
        self.assertIn("--draft=false", text)
        self.assertIn("_verify_remote_assets", text)
        self.assertIn("_rollback_pre_publish", text)
        self.assertIn("_verify_published_remote", text)
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertNotIn("--clobber", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
