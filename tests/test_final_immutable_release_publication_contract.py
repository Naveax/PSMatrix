from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts" / "ga" / "final-immutable-release-publication-contract.json"
READINESS = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_final_release_candidate.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("final_release_candidate_builder_for_publication_contract", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalImmutableReleasePublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.readiness = json.loads(READINESS.read_text(encoding="utf-8"))
        cls.builder = load_builder()

    def test_contract_identity_and_frozen_release_target(self) -> None:
        self.assertEqual(self.contract["schema"], 1)
        self.assertEqual(self.contract["kind"], "psmatrix.final-immutable-release-publication-contract")
        self.assertEqual(self.contract["version"], "2.0.0")
        self.assertEqual(self.contract["repository"], "Naveax/PSMatrix")
        release = self.contract["release"]
        self.assertEqual(release["tag"], "v2.0.0")
        self.assertEqual(release["target_commit"], self.readiness["final_release_commit"])
        self.assertNotEqual(release["target_commit"], self.readiness["producer_source_anchor"])
        self.assertTrue(release["immutable_releases_required"])
        self.assertTrue(release["draft_before_asset_upload"])
        self.assertFalse(release["prerelease"])

    def test_first_six_assets_equal_final_deterministic_builder_outputs(self) -> None:
        assets = self.contract["publication_assets"]
        self.assertEqual(self.contract["publication_asset_count"], 8)
        self.assertEqual(len(assets), 8)
        names = [row["name"] for row in assets]
        release_name = f"psmatrix-{self.builder._FINAL_VERSION}"
        expected = [
            f"{release_name}-py3-none-any.whl",
            f"{release_name}-source.zip",
            f"{release_name}-source.tar.gz",
            f"{release_name}-windows-workers.zip",
            f"{release_name}-windows-certification-kit.zip",
            f"{release_name}-windows-provisioning-kit.zip",
        ]
        self.assertEqual(names[:6], expected)
        self.assertEqual(names[6:], ["psmatrix-2.0.0-release.json", "psmatrix-2.0.0-release-public.pem"])
        self.assertEqual(len(set(names)), 8)

    def test_consumer_assets_and_control_evidence_are_disjoint(self) -> None:
        assets = {row["name"] for row in self.contract["publication_assets"]}
        excluded = set(self.contract["excluded_control_evidence"])
        self.assertFalse(assets & excluded)
        self.assertEqual(
            excluded,
            {
                "final-release-signing-status.json",
                "final-release-lock.json",
                "release-signing-run-verification.json",
                "SHA256SUMS.txt",
            },
        )
        self.assertTrue(self.contract["safety"]["control_evidence_must_not_be_publication_asset"])

    def test_six_product_digests_come_from_signed_manifest(self) -> None:
        assets = self.contract["publication_assets"]
        for row in assets[:6]:
            self.assertEqual(row["digest_source"], "signed_release_manifest")
        self.assertEqual(assets[6]["digest_source"], "protected_release_bundle")
        self.assertEqual(assets[7]["digest_source"], "active_final_release_lock")

    def test_publication_order_is_draft_upload_verify_then_publish(self) -> None:
        order = self.contract["publication_order"]
        self.assertEqual(
            order,
            [
                "verify_release_closure_readiness",
                "verify_protected_release_bundle_content",
                "enable_repository_immutable_releases",
                "create_draft_release_at_frozen_final_release_commit",
                "upload_exact_publication_asset_set",
                "verify_draft_release_asset_set",
                "publish_release",
                "verify_published_release_is_immutable",
            ],
        )
        self.assertLess(order.index("create_draft_release_at_frozen_final_release_commit"), order.index("upload_exact_publication_asset_set"))
        self.assertLess(order.index("upload_exact_publication_asset_set"), order.index("verify_draft_release_asset_set"))
        self.assertLess(order.index("verify_draft_release_asset_set"), order.index("publish_release"))

    def test_contract_lives_inside_frozen_additive_hardening_boundary(self) -> None:
        relative = CONTRACT.relative_to(ROOT).as_posix()
        self.assertEqual(relative, "scripts/ga/final-immutable-release-publication-contract.json")

    def test_source_contract_does_not_claim_execution_or_release_closure(self) -> None:
        safety = self.contract["safety"]
        self.assertTrue(safety["ga_execution_control_head_is_not_release_tag_target"])
        self.assertTrue(safety["asset_set_must_be_exact_before_publish"])
        self.assertTrue(safety["post_publish_asset_mutation_forbidden"])
        self.assertTrue(safety["post_publish_tag_mutation_forbidden"])
        self.assertFalse(safety["source_contract_executes_publication"])
        self.assertFalse(safety["release_closed"])


if __name__ == "__main__":
    unittest.main()
