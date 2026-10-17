from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CIExactEventShaCheckoutTests(unittest.TestCase):
    def test_checkout_fetches_immutable_event_sha_not_mutable_pr_ref(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("& git fetch --no-tags origin $expected", source)
        self.assertNotIn("& git fetch --no-tags origin $eventRef", source)
        self.assertIn("Exact event SHA fetch failed:", source)
        self.assertIn("for ($attempt = 1; $attempt -le 3; $attempt++)", source)
        self.assertIn("Frozen branch-object fetch attempt $attempt failed", source)
        self.assertIn("Exact event SHA fetch attempt $attempt failed", source)
        self.assertIn("Start-Sleep -Seconds (2 * $attempt)", source)
        self.assertIn("GIT_HTTP_LOW_SPEED_LIMIT", source)
        self.assertIn("GIT_HTTP_LOW_SPEED_TIME", source)
        self.assertIn("Fetched event SHA $fetched does not match GITHUB_SHA $expected.", source)

    def test_event_ref_is_still_validated_but_not_used_as_checkout_identity(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("$eventRef = [string]$env:GITHUB_REF", source)
        self.assertIn("Unsupported CI event ref:", source)
        fetch = source.index("& git fetch --no-tags origin $expected")
        checkout = source.index("& git checkout --detach --force $expected")
        self.assertLess(fetch, checkout)


    def test_frozen_finalv2_guard_isolated_base_and_protected_head(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        frozen = (ROOT / "tests" / "test_final_v2_release_control_migration.py").read_text(encoding="utf-8")
        self.assertIn("self.assertEqual(changed, allowed)", frozen)
        self.assertIn("self.assertEqual(len(changed), 55)", frozen)
        self.assertIn("github.event.pull_request.base.sha", source)
        self.assertIn("github.event_name", source)
        self.assertIn("$env:GITHUB_EVENT_NAME -eq 'pull_request'", source)
        self.assertIn("$env:GITHUB_REF -eq 'refs/heads/main'", source)
        self.assertIn("git merge-base --is-ancestor $baseSha HEAD", source)
        self.assertIn("git log --full-history -m --pretty=format: --name-only --no-renames", source)
        self.assertIn("$approvedPolicyPaths -cnotcontains $_", source)
        self.assertIn("throw 'Frozen Final-V2 non-policy protected paths were edited after immutable control base.'", source)
        self.assertLess(
            source.index("if ($unexpectedProtected.Count -ne 0)"),
            source.index("git rev-list --first-parent --max-count=512 HEAD"),
        )
        self.assertIn("git rev-list --first-parent --max-count=512 HEAD", source)
        self.assertIn("git diff --no-renames --name-only $finalSource $candidate --", source)
        self.assertIn("Compare-Object -ReferenceObject $protected", source)
        self.assertIn("git log --full-history --pretty=format: --name-only --no-renames", source)
        self.assertIn("$protected -ccontains $_", source)
        self.assertIn("& git worktree add --detach -- $frozenRoot $frozenSha", source)
        self.assertIn("& python -m unittest $module -v", source)
        self.assertIn("& git worktree remove --force -- $frozenRoot", source)
        self.assertIn("throw 'Frozen Final-V2 historical test failed.'", source)
        self.assertIn("throw 'Protected Frozen Final-V2 paths changed after the verified historical checkpoint.'", source)


    def test_second_parent_protected_edit_is_not_hidden_by_ours_merge(self) -> None:
        """A merge retaining the original tree must not erase forbidden second-parent history."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        guard = "git log --full-history -m --pretty=format: --name-only --no-renames"
        self.assertIn(guard, workflow)
        self.assertNotIn(
            "git log --first-parent -m --pretty=format: --name-only --no-renames",
            workflow,
        )
        protected = "tests/test_final_v2_release_control_migration.py"
        with tempfile.TemporaryDirectory(prefix="psmatrix-frozen-second-parent-") as folder:
            root = Path(folder)

            def git(*args: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(root), *args],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "PSMatrix Frozen Guard Fixture")
            git("config", "user.email", "guard-fixture@localhost")
            git("config", "core.autocrlf", "false")
            path = root / protected
            path.parent.mkdir(parents=True)
            original = b"# immutable historical test source\n"
            path.write_bytes(original)
            git("add", "--", protected)
            git("commit", "-q", "-m", "immutable source baseline")
            control_sha = git("rev-parse", "HEAD")

            git("switch", "-q", "-c", "poison")
            path.write_bytes(original + b"# unauthorized side-parent edit\n")
            git("add", "--", protected)
            git("commit", "-q", "-m", "forbidden protected edit")
            git("switch", "-q", "-c", "legitimate", control_sha)
            git("merge", "-q", "-s", "ours", "--no-ff", "-m", "retain original bytes", "poison")
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(git("diff", "--name-only", control_sha, "HEAD"), "")

            first_parent_only = git(
                "log", "--first-parent", "-m", "--pretty=format:",
                "--name-only", "--no-renames", control_sha + "..HEAD", "--",
            ).splitlines()
            self.assertNotIn(protected, first_parent_only)
            all_parents = git(
                "log", "--full-history", "-m", "--pretty=format:",
                "--name-only", "--no-renames", control_sha + "..HEAD", "--",
            ).splitlines()
            self.assertIn(protected, all_parents)


    def test_policy_baseline_is_not_reflagged_by_feature_merge_second_parent(self) -> None:
        """Git -m may report an approved policy delta against a stale feature parent."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "git log --full-history --pretty=format: --name-only --no-renames",
            workflow,
        )
        policy = ".github/workflows/ci.yml"
        feature = "docs/windows-lab-example.md"
        with tempfile.TemporaryDirectory(prefix="psmatrix-policy-merge-") as folder:
            root = Path(folder)

            def git(*args: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(root), *args],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "PSMatrix Frozen Guard Fixture")
            git("config", "user.email", "guard-fixture@localhost")
            git("config", "core.autocrlf", "false")
            policy_file = root / policy
            policy_file.parent.mkdir(parents=True)
            policy_file.write_text("baseline\n", encoding="utf-8")
            git("add", "--", policy)
            git("commit", "-q", "-m", "immutable control base")
            control_sha = git("rev-parse", "HEAD")

            git("switch", "-q", "-c", "policy")
            policy_file.write_text("approved policy update\n", encoding="utf-8")
            git("add", "--", policy)
            git("commit", "-q", "-m", "approved CI guard update")
            approved_sha = git("rev-parse", "HEAD")

            git("switch", "-q", "-c", "feature", control_sha)
            feature_file = root / feature
            feature_file.parent.mkdir(parents=True)
            feature_file.write_text("unrelated feature\n", encoding="utf-8")
            git("add", "--", feature)
            git("commit", "-q", "-m", "unrelated feature change")
            git("switch", "-q", "policy")
            git("merge", "-q", "--no-ff", "-m", "merge unrelated feature", "feature")

            full_dag = git(
                "log", "--full-history", "-m", "--pretty=format:",
                "--name-only", "--no-renames", control_sha + "..HEAD", "--",
            ).splitlines()
            self.assertIn(policy, full_dag)
            self.assertIn(feature, full_dag)

            after_snapshot_with_merge_diff = git(
                "log", "--full-history", "-m", "--pretty=format:",
                "--name-only", "--no-renames", approved_sha + "..HEAD", "--",
            ).splitlines()
            self.assertIn(policy, after_snapshot_with_merge_diff)
            after_snapshot_without_merge_diff = git(
                "log", "--full-history", "--pretty=format:",
                "--name-only", "--no-renames", approved_sha + "..HEAD", "--",
            ).splitlines()
            self.assertNotIn(policy, after_snapshot_without_merge_diff)
            self.assertIn(feature, after_snapshot_without_merge_diff)


if __name__ == "__main__":
    unittest.main()
