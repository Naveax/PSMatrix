from __future__ import annotations

import base64
import importlib.util
import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "collect_production_execution_anchor.py"

spec = importlib.util.spec_from_file_location("production_execution_anchor_collector", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
anchor = module.anchor_verifier
readiness = module.readiness_verifier


class ProductionExecutionAnchorCollectorTests(unittest.TestCase):
    def _contract(self) -> dict:
        paths = [anchor.READINESS_PATH] + [
            f".github/workflows/ga-test-{index:02d}.yml" for index in range(1, 19)
        ]
        return {
            "schema": 1,
            "kind": "psmatrix.final-production-bootstrap-contract",
            "version": "2.0.0",
            "execution_control_head": anchor.EXPECTED_BOOTSTRAP_CONTROL_HEAD,
            "final_release_commit": anchor.EXPECTED_FINAL_RELEASE_COMMIT,
            "default_branch": "main",
            "required_dispatch_workflow_paths": paths,
            "requirements": {
                "default_branch_publication_required_before_any_production_dispatch": True,
                "all_required_dispatch_workflow_paths_must_exist_on_default_branch": True,
                "readiness_source_preflight_success_required": True,
                "production_readiness_pass_required_before_lock_bootstrap": True,
                "review_and_promotion_runs_must_share_exact_control_head": True,
                "exact_repository_commit_required_before_signing": True,
                "active_lock_and_public_key_must_both_exist_before_signed_release": True,
                "automatic_production_dispatch_allowed_from_source_preflight": False,
                "automatic_merge_allowed": False,
                "ga_eligibility_before_full_evidence_and_final_attestation": False,
            },
        }

    def _readiness_run(self, *, conclusion: str = "failure") -> dict:
        return {
            "id": 31465317589,
            "run_number": 1,
            "name": anchor.READINESS_WORKFLOW,
            "path": anchor.READINESS_PATH,
            "event": "workflow_dispatch",
            "head_sha": anchor.EXPECTED_ANCHOR_HEAD,
            "head_branch": anchor.EXPECTED_REF,
            "status": "completed",
            "conclusion": conclusion,
            "created_at": "2026-08-11T06:30:10Z",
        }

    def _content_response(self, raw: bytes, *, sha: str = "1" * 40) -> dict:
        return {
            "type": "file",
            "encoding": "base64",
            "content": base64.b64encode(raw).decode("ascii"),
            "sha": sha,
        }

    def _api(
        self,
        *,
        moved_branch: bool = False,
        bad_dispatch_path: str | None = None,
        expired_artifact: bool = False,
        readiness_conclusion: str = "failure",
    ):
        contract = self._contract()
        run = self._readiness_run(conclusion=readiness_conclusion)

        def api_get(endpoint: str):
            if endpoint.startswith("repos/Naveax/PSMatrix/branches/"):
                return {
                    "name": anchor.EXPECTED_REF,
                    "commit": {
                        "sha": "f" * 40 if moved_branch else anchor.EXPECTED_ANCHOR_HEAD
                    },
                }
            if endpoint == f"repos/Naveax/PSMatrix/commits/{anchor.EXPECTED_ANCHOR_HEAD}":
                return {
                    "sha": anchor.EXPECTED_ANCHOR_HEAD,
                    "commit": {
                        "tree": {"sha": anchor.EXPECTED_ANCHOR_TREE},
                        "verification": {"verified": True},
                    },
                }
            if endpoint == (
                f"repos/Naveax/PSMatrix/compare/{anchor.EXPECTED_BOOTSTRAP_CONTROL_HEAD}"
                f"...{anchor.EXPECTED_ANCHOR_HEAD}"
            ):
                return {
                    "status": "ahead",
                    "ahead_by": 48,
                    "behind_by": 0,
                    "base_commit": {"sha": anchor.EXPECTED_BOOTSTRAP_CONTROL_HEAD},
                    "merge_base_commit": {"sha": anchor.EXPECTED_BOOTSTRAP_CONTROL_HEAD},
                }
            if endpoint.startswith("repos/Naveax/PSMatrix/contents/"):
                parsed = urlparse("https://api.invalid/" + endpoint)
                path = unquote(parsed.path.split("/contents/", 1)[1])
                ref = parse_qs(parsed.query).get("ref")
                self.assertEqual(ref, [anchor.EXPECTED_ANCHOR_HEAD])
                if path == module.BOOTSTRAP_PATH:
                    return self._content_response(json.dumps(contract).encode("utf-8"))
                if path not in contract["required_dispatch_workflow_paths"]:
                    raise AssertionError(f"unexpected content path: {path}")
                text = "name: test\non:\n  workflow_dispatch:\n"
                if bad_dispatch_path == path:
                    text = "name: test\non:\n  push:\n"
                return self._content_response(text.encode("utf-8"))
            if endpoint.startswith("repos/Naveax/PSMatrix/actions/runs?"):
                query = parse_qs(urlparse("https://api.invalid/" + endpoint).query)
                self.assertEqual(query.get("event"), ["workflow_dispatch"])
                self.assertEqual(query.get("head_sha"), [anchor.EXPECTED_ANCHOR_HEAD])
                return {"total_count": 1, "workflow_runs": [run]}
            if endpoint == f"repos/Naveax/PSMatrix/actions/runs/{run['id']}":
                return dict(run)
            if endpoint.startswith(
                f"repos/Naveax/PSMatrix/actions/runs/{run['id']}/artifacts?"
            ):
                return {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "id": 9091355778,
                            "name": readiness.EXPECTED_ARTIFACT,
                            "expired": expired_artifact,
                        }
                    ],
                }
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        return api_get

    def test_live_shape_failure_is_verified_provenance_and_blocked_readiness(self) -> None:
        value = module.collect(api_get=self._api())
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_READINESS")
        self.assertTrue(value["publication_anchor_verified"])
        self.assertTrue(value["dispatch_sources_verified"])
        self.assertEqual(value["dispatch_source_count"], 19)
        self.assertEqual(value["workflow_dispatch_run_count"], 1)
        self.assertEqual(value["readiness_run_count"], 1)
        self.assertEqual(value["post_readiness_run_count"], 0)
        self.assertTrue(value["latest_readiness_artifact_provenance_verified"])
        receipt = value["latest_readiness_run_api_verification"]
        self.assertEqual(receipt["run_conclusion"], "failure")
        self.assertFalse(receipt["readiness_pass_observed"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_successful_readiness_still_waits_for_summary_content_verification(self) -> None:
        value = module.collect(api_get=self._api(readiness_conclusion="success"))
        self.assertEqual(
            value["current_stage"], "READINESS_RUN_SUCCESS_AWAITING_CONTENT_VERIFICATION"
        )
        self.assertTrue(value["latest_readiness_artifact_provenance_verified"])
        self.assertTrue(
            value["latest_readiness_run_api_verification"]["readiness_pass_observed"]
        )
        self.assertFalse(value["readiness_summary_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_branch_movement_is_rejected(self) -> None:
        with self.assertRaises(module.ProductionExecutionAnchorCollectionError):
            module.collect(api_get=self._api(moved_branch=True))

    def test_each_of_exact_19_anchor_workflows_must_remain_dispatchable(self) -> None:
        bad = ".github/workflows/ga-test-07.yml"
        with self.assertRaises(module.ProductionExecutionAnchorCollectionError):
            module.collect(api_get=self._api(bad_dispatch_path=bad))

    def test_expired_readiness_artifact_is_rejected(self) -> None:
        with self.assertRaises(module.ProductionExecutionAnchorCollectionError):
            module.collect(api_get=self._api(expired_artifact=True))

    def test_repository_scope_is_frozen(self) -> None:
        with self.assertRaises(module.ProductionExecutionAnchorCollectionError):
            module.collect(repository="SomeoneElse/PSMatrix", api_get=self._api())


if __name__ == "__main__":
    unittest.main()
