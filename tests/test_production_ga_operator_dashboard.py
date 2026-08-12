from __future__ import annotations

import importlib.util
from pathlib import Path

_BASE_PATH = Path(__file__).with_name("_production_ga_operator_dashboard_base.py")


def _load_base():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_production_ga_operator_dashboard_test_base",
        _BASE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production GA dashboard test base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_base = _load_base()


class ProductionGAOperatorDashboardTests(_base.ProductionGAOperatorDashboardTests):
    def immutable(self) -> dict:
        value = super().immutable()
        value["publication_asset_count"] = 9
        value["final_ga_attestation_public_asset_verified"] = True
        return value

    def documentation(self) -> dict:
        value = super().documentation()
        value["immutable_publication_asset_count"] = 9
        return value

    def cleanup(self) -> dict:
        value = super().cleanup()
        value["immutable_publication_asset_count"] = 9
        return value

    def final_release(self) -> dict:
        value = super().final_release()
        value["publication_asset_count"] = 9
        value["final_ga_attestation_public_asset_verified"] = True
        return value

    def test_old_eight_asset_receipts_never_advance_post_ga_dashboard(self) -> None:
        immutable = self.immutable()
        immutable["publication_asset_count"] = 8
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=immutable,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE")
        self.assertFalse(value["immutable_release_verified"])

        documentation = self.documentation()
        documentation["immutable_publication_asset_count"] = 8
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=self.immutable(),
            documentation_verification=documentation,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "VERIFY_FINAL_DOCUMENTATION_STATE")
        self.assertFalse(value["documentation_final_state_closed"])

        cleanup = self.cleanup()
        cleanup["immutable_publication_asset_count"] = 8
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=self.immutable(),
            documentation_verification=self.documentation(),
            cleanup_verification=cleanup,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "CLEAN_AND_VERIFY_STALE_RELEASE_WORK")
        self.assertFalse(value["stale_branch_pr_cleanup_completed"])

        final = self.final_release()
        final["publication_asset_count"] = 8
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=self.immutable(),
            documentation_verification=self.documentation(),
            cleanup_verification=self.cleanup(),
            final_repository_scan=self.scan(),
            final_release_verification=final,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "VERIFY_FINAL_RELEASE_CLOSURE")
        self.assertFalse(value["final_release_closure_verified"])
        self.assertFalse(value["release_closed"])

    def test_missing_final_ga_attestation_public_asset_proof_never_advances(self) -> None:
        immutable = self.immutable()
        immutable["final_ga_attestation_public_asset_verified"] = False
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=immutable,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE")
        self.assertFalse(value["immutable_release_verified"])

        final = self.final_release()
        final["final_ga_attestation_public_asset_verified"] = False
        value = self.module.build(
            self.inventory(),
            self.summary(),
            immutable_release_verification=self.immutable(),
            documentation_verification=self.documentation(),
            cleanup_verification=self.cleanup(),
            final_repository_scan=self.scan(),
            final_release_verification=final,
            **self.post_ga_base(),
        )
        self.assertEqual(value["stage"], "VERIFY_FINAL_RELEASE_CLOSURE")
        self.assertFalse(value["final_release_closure_verified"])
        self.assertFalse(value["release_closed"])

    def test_publication_next_action_reports_exact_nine_assets(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), **self.post_ga_base())
        self.assertEqual(value["stage"], "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE")
        self.assertIn("9/9", value["next_action"])
        self.assertNotIn("8/8", value["next_action"])


if __name__ == "__main__":
    import unittest
    unittest.main()
