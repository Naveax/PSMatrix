from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_BASE_PATH = Path(__file__).with_name("_final_immutable_release_verification_base.py")


def _load_base():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_immutable_release_verification_test_base",
        _BASE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load immutable release verification test base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_base = _load_base()


class FinalImmutableReleaseVerificationTests(
    _base.FinalImmutableReleaseVerificationTests
):
    def setUp(self) -> None:
        super().setUp()
        self.publication_contract["publication_asset_count"] = 9
        self.publication_contract["safety"] = {
            "final_ga_attestation_bundle_must_be_publication_asset": True,
            "final_ga_attestation_bundle_must_match_verified_execution_head": True,
        }
        self.publication_operation["publication_asset_count"] = 9
        self.publication_operation["current_final_ga_attestation_public_asset_reverified"] = True
        self.publication_operation["final_ga_attestation_public_asset_execution_head_verified"] = True
        self.publication_operation[
            "publication_receipt_output_reserved_before_mutation"
        ] = True

    def test_immutable_release_with_exact_assets_and_attestation_passes(self) -> None:
        value = self.verify()
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["tagged_commit"], self.release_commit)
        self.assertEqual(value["release_execution_control_head"], self.execution_head)
        self.assertEqual(value["publication_asset_count"], 9)
        self.assertTrue(value["publication_operation_verified"])
        self.assertTrue(value["release_asset_set_verified"])
        self.assertTrue(value["final_ga_attestation_public_asset_verified"])
        self.assertTrue(value["github_release_attestation_verified"])
        self.assertTrue(value["repository_immutable_releases_enabled"])
        self.assertTrue(value["release_object_immutable"])
        self.assertTrue(value["final_immutable_ga_anchor_created"])
        self.assertFalse(value["release_closed"])

    def test_publication_operation_requires_reserved_output_before_mutation(self) -> None:
        field = "publication_receipt_output_reserved_before_mutation"
        self.publication_operation.pop(field)
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.publication_operation[field] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_publication_operation_requires_current_final_ga_asset_reverification(self) -> None:
        for field in (
            "current_final_ga_attestation_public_asset_reverified",
            "final_ga_attestation_public_asset_execution_head_verified",
        ):
            with self.subTest(field=field):
                self.publication_operation[field] = False
                with self.assertRaises(self.module.FinalImmutableReleaseError):
                    self.verify()
                self.setUp()

    def test_eight_asset_remote_release_is_rejected(self) -> None:
        self.release["assets"] = self.release["assets"][:-1]
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_final_ga_attestation_remote_digest_drift_is_rejected(self) -> None:
        last = dict(self.release["assets"][-1])
        last["digest"] = "sha256:" + "f" * 64
        self.release["assets"][-1] = last
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_verification_receipt_carries_reservation_and_final_ga_asset_binding(self) -> None:
        value = self.verify()
        self.assertTrue(
            value["publication_receipt_output_reserved_before_mutation"]
        )
        self.assertTrue(value["final_ga_attestation_public_asset_verified"])
        self.assertEqual(value["publication_asset_count"], 9)

    def test_source_queries_current_api_and_cryptographically_verifies_release_attestation(self) -> None:
        script = Path(self.module.__file__)
        impl = script.with_name("_verify_final_immutable_release_impl.py")
        extension = script.with_name("_verify_final_immutable_release_nine_asset.py")
        text = (
            script.read_text(encoding="utf-8")
            + "\n"
            + impl.read_text(encoding="utf-8")
            + "\n"
            + extension.read_text(encoding="utf-8")
        )
        self.assertIn('API_VERSION = "2026-03-10"', text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("immutable-releases", text)
        self.assertIn("releases/tags/", text)
        self.assertIn("git/ref/tags/", text)
        self.assertIn('"release", "verify"', text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("publication_operation_verified", text)
        self.assertIn("final_ga_attestation_public_asset_verified", text)
        self.assertIn("psmatrix-2.0.0-final-ga-attestation.zip", text)
        self.assertIn("final_immutable_ga_anchor_created", text)
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
