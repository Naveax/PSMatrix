from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "cleanup_stale_release_work.py"


def load_module():
    spec = importlib.util.spec_from_file_location("stale_release_work_cleanup_operator", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_closure(head: str = "a" * 40) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.release-closure-readiness",
        "version": "2.0.0",
        "status": "READY_FOR_RELEASE_CLOSURE",
        "execution_head": head,
        "ga_eligible": True,
        "release_closed": False,
    }


def immutable_release(head: str = "a" * 40) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.final-immutable-release-verification",
        "version": "2.0.0",
        "status": "PASS",
        "tag": "v2.0.0",
        "release_execution_control_head": head,
        "release_published": True,
        "final_immutable_ga_anchor_created": True,
        "release_closed": False,
    }


class StaleReleaseWorkCleanupOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.verifier = self.module._load_verifier()
        self.closure = release_closure()
        self.immutable = immutable_release()

    def test_dry_run_plans_stale_branch_without_delete(self) -> None:
        branches = [{"name": "main"}, {"name": "prod/old-hardening"}]
        pulls: list[dict[str, object]] = []

        def fake_paged(_gh: str, endpoint: str):
            return pulls if "pulls?state=open" in endpoint else branches

        with (
            patch.object(self.module, "_paged_list", side_effect=fake_paged),
            patch.object(
                self.module,
                "_branch_ref",
                return_value={"branch": "prod/old-hardening", "sha": "b" * 40},
            ),
            patch.object(self.module, "_gh_delete", side_effect=AssertionError("dry-run attempted DELETE")),
        ):
            receipt, verification = self.module.run_operation(
                self.closure, self.immutable, "Naveax/PSMatrix", "gh", False
            )

        self.assertEqual(receipt["status"], "DRY_RUN")
        self.assertEqual(receipt["repository"], "Naveax/PSMatrix")
        self.assertEqual(receipt["stale_branch_count"], 1)
        self.assertEqual(receipt["stale_branches"][0]["branch"], "prod/old-hardening")
        self.assertFalse(receipt["mutation_executed"])
        self.assertTrue(receipt["delete_requires_explicit_execute"])
        self.assertFalse(receipt["stale_branch_pr_cleanup_completed"])
        self.assertIsNone(verification)

    def test_execute_refuses_stale_open_pr_without_mutation(self) -> None:
        branches = [{"name": "main"}, {"name": "prod/open-work"}]
        pulls = [
            {
                "number": 88,
                "state": "open",
                "head": {"ref": "prod/open-work"},
            }
        ]
        targets = [{"branch": "prod/open-work", "sha": "b" * 40}]
        plan = self.module.build_plan(
            self.verifier, self.closure, self.immutable, branches, pulls, targets
        )
        with (
            patch.object(self.module, "_gh_delete", side_effect=AssertionError("stale PR path attempted DELETE")),
            self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
        ):
            self.module.execute_plan(
                self.verifier,
                plan,
                self.closure,
                self.immutable,
                "Naveax/PSMatrix",
                "gh",
            )

    def test_allowed_anchors_are_never_planned_for_delete(self) -> None:
        branches = [
            {"name": "main"},
            {"name": "final/2.0.0-production-control-plane-publication-anchor"},
            {"name": "final/2.0.0-verification-hardening-publication-anchor"},
            {"name": "final/2.0.0-ga-publication-anchor"},
        ]
        plan = self.module.build_plan(
            self.verifier, self.closure, self.immutable, branches, [], []
        )
        self.assertEqual(plan["stale_branch_count"], 0)
        self.assertEqual(plan["stale_branches"], [])

    def test_execute_deletes_only_exact_stale_targets_then_reuses_verifier(self) -> None:
        branches_before = [
            {"name": "main"},
            {"name": "feature/keep-unrelated"},
            {"name": "prod/old-one"},
            {"name": "work/old-two"},
        ]
        plan = self.module.build_plan(
            self.verifier,
            self.closure,
            self.immutable,
            branches_before,
            [],
            [
                {"branch": "prod/old-one", "sha": "b" * 40},
                {"branch": "work/old-two", "sha": "c" * 40},
            ],
        )
        refs = {
            "prod/old-one": {"branch": "prod/old-one", "sha": "b" * 40},
            "work/old-two": {"branch": "work/old-two", "sha": "c" * 40},
        }
        deleted: list[str] = []

        def fake_ref(_gh: str, _repository: str, branch: str):
            return dict(refs[branch])

        def fake_delete(_gh: str, endpoint: str):
            deleted.append(endpoint)

        def fake_paged(_gh: str, endpoint: str):
            if "pulls?state=open" in endpoint:
                return []
            return [{"name": "main"}, {"name": "feature/keep-unrelated"}]

        with (
            patch.object(self.module, "_branch_ref", side_effect=fake_ref),
            patch.object(self.module, "_gh_delete", side_effect=fake_delete),
            patch.object(self.module, "_paged_list", side_effect=fake_paged),
        ):
            receipt, verification = self.module.execute_plan(
                self.verifier,
                plan,
                self.closure,
                self.immutable,
                "Naveax/PSMatrix",
                "gh",
            )

        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["repository"], "Naveax/PSMatrix")
        self.assertEqual(receipt["deleted_branch_count"], 2)
        self.assertTrue(receipt["mutation_executed"])
        self.assertTrue(receipt["post_delete_verification_passed"])
        self.assertTrue(receipt["stale_branch_pr_cleanup_completed"])
        self.assertEqual(verification["status"], "PASS")
        self.assertEqual(verification["repository"], "Naveax/PSMatrix")
        self.assertTrue(verification["stale_branch_pr_cleanup_completed"])
        self.assertEqual(len(deleted), 2)
        self.assertTrue(all("%2F" in endpoint for endpoint in deleted))
        self.assertTrue(all("feature%2Fkeep-unrelated" not in endpoint for endpoint in deleted))

    def test_target_drift_fails_before_delete(self) -> None:
        branches = [{"name": "main"}, {"name": "prod/drift"}]
        plan = self.module.build_plan(
            self.verifier,
            self.closure,
            self.immutable,
            branches,
            [],
            [{"branch": "prod/drift", "sha": "b" * 40}],
        )
        with (
            patch.object(
                self.module,
                "_branch_ref",
                return_value={"branch": "prod/drift", "sha": "c" * 40},
            ),
            patch.object(self.module, "_gh_delete", side_effect=AssertionError("drift path attempted DELETE")),
            self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
        ):
            self.module.execute_plan(
                self.verifier,
                plan,
                self.closure,
                self.immutable,
                "Naveax/PSMatrix",
                "gh",
            )

    def test_post_delete_failure_restores_previously_deleted_refs(self) -> None:
        branches = [{"name": "main"}, {"name": "prod/one"}, {"name": "prod/two"}]
        plan = self.module.build_plan(
            self.verifier,
            self.closure,
            self.immutable,
            branches,
            [],
            [
                {"branch": "prod/one", "sha": "b" * 40},
                {"branch": "prod/two", "sha": "c" * 40},
            ],
        )
        refs = {
            "prod/one": {"branch": "prod/one", "sha": "b" * 40},
            "prod/two": {"branch": "prod/two", "sha": "c" * 40},
        }
        restored: list[tuple[str, str]] = []

        def fake_ref(_gh: str, _repository: str, branch: str):
            return dict(refs[branch])

        def fake_paged(_gh: str, endpoint: str):
            if "pulls?state=open" in endpoint:
                return []
            return [{"name": "main"}, {"name": "prod/two"}]

        with (
            patch.object(self.module, "_branch_ref", side_effect=fake_ref),
            patch.object(self.module, "_gh_delete", return_value=None),
            patch.object(self.module, "_paged_list", side_effect=fake_paged),
            patch.object(
                self.module,
                "_gh_create_ref",
                side_effect=lambda _gh, _repo, branch, sha: restored.append((branch, sha)),
            ),
            self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
        ):
            self.module.execute_plan(
                self.verifier,
                plan,
                self.closure,
                self.immutable,
                "Naveax/PSMatrix",
                "gh",
            )

        self.assertEqual(
            restored,
            [("prod/two", "c" * 40), ("prod/one", "b" * 40)],
        )

    def test_invalid_immutable_release_is_rejected_before_planning(self) -> None:
        bad = dict(self.immutable)
        bad["release_published"] = False
        with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
            self.module.build_plan(self.verifier, self.closure, bad, [{"name": "main"}], [], [])

    def test_receipt_head_mismatch_is_rejected_before_planning(self) -> None:
        bad = dict(self.immutable)
        bad["release_execution_control_head"] = "b" * 40
        with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
            self.module.build_plan(self.verifier, self.closure, bad, [{"name": "main"}], [], [])

    def test_wrong_repository_is_rejected_before_any_api_or_delete(self) -> None:
        with (
            patch.object(self.module, "_paged_list", side_effect=AssertionError("wrong repo reached API")),
            patch.object(self.module, "_gh_delete", side_effect=AssertionError("wrong repo reached DELETE")),
            self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
        ):
            self.module.run_operation(
                self.closure,
                self.immutable,
                "someone-else/PSMatrix",
                "gh",
                False,
            )

    def test_source_reuses_repository_verifier_and_requires_explicit_execute(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("verify_stale_release_work_cleanup.py", text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("--execute", text)
        self.assertIn("delete_requires_explicit_execute", text)
        self.assertIn("rollback_supported", text)
        self.assertIn("_gh_create_ref", text)
        self.assertIn("post_delete_verification_passed", text)
        self.assertIn("release_closed", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
