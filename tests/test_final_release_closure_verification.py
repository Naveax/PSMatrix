from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_BASE_PATH = Path(__file__).with_name("_final_release_closure_verification_base.py")


def _load_base():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_verification_test_base",
        _BASE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load final release closure verification test base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_base = _load_base()


class FinalReleaseClosureVerificationTests(
    _base.FinalReleaseClosureVerificationTests
):
    def setUp(self) -> None:
        super().setUp()
        self.release[
            "publication_receipt_output_reserved_before_mutation"
        ] = True

    def test_publication_reservation_proof_is_required_for_release_closed(self) -> None:
        field = "publication_receipt_output_reserved_before_mutation"
        self.release.pop(field)
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.setUp()
        self.release[field] = False
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )

    def test_cleanup_audit_transaction_proof_is_required_for_release_closed(self) -> None:
        for field in (
            "cleanup_audit_outputs_reserved_before_mutation",
            "cleanup_audit_outputs_finalized_inside_rollback_boundary",
        ):
            with self.subTest(field=field, mode="missing"):
                self.setUp()
                self.cleanup.pop(field)
                with self.assertRaises(self.module.FinalReleaseClosureError):
                    self.module.verify(
                        self.closure,
                        self.release,
                        self.documentation,
                        self.cleanup,
                        self.scan,
                    )
            with self.subTest(field=field, mode="false"):
                self.setUp()
                self.cleanup[field] = False
                with self.assertRaises(self.module.FinalReleaseClosureError):
                    self.module.verify(
                        self.closure,
                        self.release,
                        self.documentation,
                        self.cleanup,
                        self.scan,
                    )

        self.setUp()
        self.scan.pop("cleanup_audit_transaction_verified")
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )

    def test_release_closed_receipt_carries_bound_safety_proofs(self) -> None:
        value = self.module.verify(
            self.closure,
            self.release,
            self.documentation,
            self.cleanup,
            self.scan,
        )
        self.assertTrue(
            value["publication_receipt_output_reserved_before_mutation"]
        )
        self.assertTrue(value["cleanup_audit_transaction_verified"])

    def test_source_is_only_component_allowed_to_emit_release_closed_true(self) -> None:
        public = _base.SCRIPT
        impl = public.with_name("_verify_final_release_closure_impl.py")
        text = public.read_text(encoding="utf-8") + "\n" + impl.read_text(encoding="utf-8")
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn('"status": "RELEASE_CLOSED"', text)
        self.assertIn('"post_ga_operation_count": 6', text)
        self.assertIn('"release_closed": True', text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("post_ga_receipts_bound", text)
        self.assertIn("documentation_repository_head", text)
        self.assertIn("final_repo_secret_scan_completed", text)
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertIn("cleanup_audit_outputs_reserved_before_mutation", text)
        self.assertIn("cleanup_audit_outputs_finalized_inside_rollback_boundary", text)
        self.assertIn("cleanup_audit_transaction_verified", text)


if __name__ == "__main__":
    unittest.main()
