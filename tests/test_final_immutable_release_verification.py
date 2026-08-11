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
        self.publication_operation[
            "publication_receipt_output_reserved_before_mutation"
        ] = True

    def test_publication_operation_requires_reserved_output_before_mutation(self) -> None:
        field = "publication_receipt_output_reserved_before_mutation"
        self.publication_operation.pop(field)
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()
        self.setUp()
        self.publication_operation[field] = False
        with self.assertRaises(self.module.FinalImmutableReleaseError):
            self.verify()

    def test_verification_receipt_carries_reservation_binding(self) -> None:
        value = self.verify()
        self.assertTrue(
            value["publication_receipt_output_reserved_before_mutation"]
        )

    def test_source_queries_current_api_and_cryptographically_verifies_release_attestation(self) -> None:
        script = Path(self.module.__file__)
        impl = script.with_name("_verify_final_immutable_release_impl.py")
        text = script.read_text(encoding="utf-8") + "\n" + impl.read_text(encoding="utf-8")
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
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
