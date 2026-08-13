from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

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
        self.fresh_release_closure = dict(self.closure)
        self.release_closure_reverify_patcher = patch.object(
            self.module,
            "_reverify_release_closure_readiness",
            side_effect=lambda *_args, **_kwargs: dict(self.fresh_release_closure),
        )
        self.release_closure_reverify = self.release_closure_reverify_patcher.start()
        self.addCleanup(self.release_closure_reverify_patcher.stop)
        self.release[
            "publication_receipt_output_reserved_before_mutation"
        ] = True
        self.release["final_ga_attestation_public_asset_verified"] = True
        self.documentation_reverify_patcher = patch.object(
            self.module,
            "_reverify_current_documentation",
            side_effect=lambda *_args, **_kwargs: dict(self.documentation),
        )
        self.documentation_reverify = self.documentation_reverify_patcher.start()
        self.addCleanup(self.documentation_reverify_patcher.stop)
        self.cleanup.update(
            {
                "branch_count_observed": 4,
                "open_pr_count_observed": 0,
                "stale_prefixes": list(self.module._CLEANUP_VERIFIER.STALE_PREFIXES),
                "allowed_branches": sorted(self.module._CLEANUP_VERIFIER.ALLOWED_BRANCHES),
                "documentation_final_state_closed": False,
                "final_repo_secret_scan_completed": False,
            }
        )
        self.fresh_cleanup = self.module._canonical_cleanup_receipt(self.cleanup)
        self.cleanup_reverify_patcher = patch.object(
            self.module,
            "_reverify_current_cleanup",
            side_effect=lambda *_args, **_kwargs: dict(self.fresh_cleanup),
        )
        self.cleanup_reverify = self.cleanup_reverify_patcher.start()
        self.addCleanup(self.cleanup_reverify_patcher.stop)
        self.scan.update(
            {
                "tracked_file_count": 123,
                "scanner_repository_owned": True,
                "secret_values_emitted": False,
                "secret_hashes_emitted": False,
                "secret_lengths_emitted": False,
            }
        )
        self.fresh_final_scan = dict(self.scan)
        self.final_scan_reverify_patcher = patch.object(
            self.module,
            "_reverify_current_final_scan",
            side_effect=lambda *_args, **_kwargs: dict(self.fresh_final_scan),
        )
        self.final_scan_reverify = self.final_scan_reverify_patcher.start()
        self.addCleanup(self.final_scan_reverify_patcher.stop)

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

    def test_final_ga_attestation_public_asset_proof_is_required_for_release_closed(self) -> None:
        field = "final_ga_attestation_public_asset_verified"
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

    def test_forged_release_closure_readiness_is_rejected_when_canonical_composition_disagrees(self) -> None:
        self.closure["production_readiness_verified"] = False
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.release_closure_reverify.assert_called_once_with(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )

    def test_forged_immutable_release_receipt_is_rejected_when_fresh_authority_disagrees(self) -> None:
        fresh = dict(self.release)
        fresh["release_id"] = 78
        self.immutable_reverify.side_effect = None
        self.immutable_reverify.return_value = fresh
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.release_closure_reverify.assert_called_once_with(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        self.immutable_reverify.assert_called_once_with(self.closure, None, "gh")

    def test_forged_documentation_receipt_is_rejected_when_fresh_authority_disagrees(self) -> None:
        fresh = dict(self.documentation)
        fresh["document_count"] = 99
        self.documentation_reverify.side_effect = None
        self.documentation_reverify.return_value = fresh
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.documentation_reverify.assert_called_once_with(
            None,
            self.release,
            self.documentation,
        )

    def test_forged_cleanup_receipt_is_rejected_when_fresh_authority_disagrees(self) -> None:
        self.cleanup["allowed_branches"] = ["forged-authority"]
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.cleanup_reverify.assert_called_once_with(
            self.closure,
            self.release,
            "gh",
        )

    def test_cleanup_observation_counts_may_drift_without_weakening_live_authority(self) -> None:
        self.cleanup["branch_count_observed"] = 99
        self.cleanup["open_pr_count_observed"] = 88
        value = self.module.verify(
            self.closure,
            self.release,
            self.documentation,
            self.cleanup,
            self.scan,
        )
        self.assertTrue(value["cleanup_canonical_reverification_verified"])

    def test_forged_final_scan_receipt_is_rejected_when_fresh_authority_disagrees(self) -> None:
        self.scan["scanner_repository_owned"] = False
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(
                self.closure,
                self.release,
                self.documentation,
                self.cleanup,
                self.scan,
            )
        self.final_scan_reverify.assert_called_once_with(
            self.closure,
            self.documentation,
            self.cleanup,
        )

    def test_release_closed_receipt_carries_bound_safety_proofs(self) -> None:
        value = self.module.verify(
            self.closure,
            self.release,
            self.documentation,
            self.cleanup,
            self.scan,
        )
        self.assertTrue(value["release_closure_readiness_canonical_reverification_verified"])
        self.assertTrue(value["immutable_release_canonical_reverification_verified"])
        self.assertTrue(value["documentation_canonical_reverification_verified"])
        self.assertTrue(value["cleanup_canonical_reverification_verified"])
        self.assertTrue(value["final_repository_scan_canonical_reverification_verified"])
        self.assertTrue(
            value["publication_receipt_output_reserved_before_mutation"]
        )
        self.assertTrue(value["final_ga_attestation_public_asset_verified"])
        self.assertTrue(value["cleanup_audit_transaction_verified"])
        self.immutable_reverify.assert_called_once_with(self.closure, None, "gh")
        self.documentation_reverify.assert_called_once_with(
            None,
            self.release,
            self.documentation,
        )
        self.cleanup_reverify.assert_called_once_with(
            self.closure,
            self.release,
            "gh",
        )
        self.final_scan_reverify.assert_called_once_with(
            self.closure,
            self.documentation,
            self.cleanup,
        )

    def test_source_is_only_component_allowed_to_emit_release_closed_true(self) -> None:
        public = _base.SCRIPT
        impl = public.with_name("_verify_final_release_closure_impl.py")
        text = public.read_text(encoding="utf-8") + "\n" + impl.read_text(encoding="utf-8")
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn('"status": "RELEASE_CLOSED"', text)
        self.assertIn('"post_ga_operation_count": 6', text)
        self.assertIn('"release_closed": True', text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("final_ga_attestation_public_asset_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("post_ga_receipts_bound", text)
        self.assertIn("documentation_repository_head", text)
        self.assertIn("final_repo_secret_scan_completed", text)
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertIn("cleanup_audit_outputs_reserved_before_mutation", text)
        self.assertIn("cleanup_audit_outputs_finalized_inside_rollback_boundary", text)
        self.assertIn("cleanup_audit_transaction_verified", text)
        self.assertIn("build_release_closure_readiness.py", text)
        self.assertIn("_reverify_release_closure_readiness", text)
        self.assertIn("--production-readiness-verification", text)
        self.assertIn("--final-lock-verification", text)
        self.assertIn("--content-closure", text)
        self.assertIn("--evaluator-verification", text)
        self.assertIn("--attestation-verification", text)
        self.assertIn("release_closure_readiness_canonical_reverification_verified", text)
        self.assertIn("verify_final_immutable_release.py", text)
        self.assertIn("_reverify_current_immutable_release", text)
        self.assertIn("_verify_github_release_attestation", text)
        self.assertIn("--publication-operation", text)
        self.assertIn("immutable_release_canonical_reverification_verified", text)
        self.assertIn("verify_final_documentation_state.py", text)
        self.assertIn("_reverify_current_documentation", text)
        self.assertIn("--documentation-record", text)
        self.assertIn("documentation_canonical_reverification_verified", text)
        self.assertIn("verify_stale_release_work_cleanup.py", text)
        self.assertIn("_reverify_current_cleanup", text)
        self.assertIn("cleanup_canonical_reverification_verified", text)
        self.assertIn("certify_final_repository_private_material_scan.py", text)
        self.assertIn("_reverify_current_final_scan", text)
        self.assertIn("final_repository_scan_canonical_reverification_verified", text)


if __name__ == "__main__":
    unittest.main()
