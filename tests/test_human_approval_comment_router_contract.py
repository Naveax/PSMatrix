from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ROUTER = WORKFLOWS / "ops-human-approval-promotion-dispatch-router.yml"
RC4 = WORKFLOWS / "ops-rc4-human-approval-promotion-dispatch.yml"
FINAL = WORKFLOWS / "ops-final-human-approval-promotion-dispatch.yml"
POLICY = WORKFLOWS / "ops-workflow-policy-verify.yml"


class HumanApprovalCommentRouterContractTests(unittest.TestCase):
    def test_only_router_subscribes_to_issue_comment(self) -> None:
        approval_workflows = (
            ROUTER,
            RC4,
            FINAL,
        )
        listeners = []
        for path in approval_workflows:
            text = path.read_text(encoding="utf-8")
            if "issue_comment:" in text:
                listeners.append(path.name)
        self.assertEqual(listeners, [ROUTER.name])

    def test_router_preserves_exact_human_gate_predicates(self) -> None:
        text = ROUTER.read_text(encoding="utf-8")
        required = (
            "github.event.issue.number == 260",
            "github.event.issue.number == 263",
            "github.event.comment.user.login == 'Naveax'",
            "github.event.comment.author_association == 'OWNER'",
            "github.event.comment.body == 'RC4 HUMAN REVIEW APPROVED: 0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63'",
            "startsWith(github.event.comment.body, 'FINAL HUMAN REVIEW APPROVED: ')",
            "uses: ./.github/workflows/ops-rc4-human-approval-promotion-dispatch.yml",
            "uses: ./.github/workflows/ops-final-human-approval-promotion-dispatch.yml",
        )
        for value in required:
            with self.subTest(required=value):
                self.assertIn(value, text)

    def test_router_and_called_workflows_keep_least_privilege_and_concurrency_boundaries(self) -> None:
        router = ROUTER.read_text(encoding="utf-8")
        rc4 = RC4.read_text(encoding="utf-8")
        final = FINAL.read_text(encoding="utf-8")

        self.assertIn("concurrency:\n  group: ops-human-approval-comment-router-${{ github.event.comment.id }}\n  cancel-in-progress: false", router)
        self.assertIn("permissions:\n  contents: read\n", router)
        self.assertIn("actions: write\n      issues: write", router)
        self.assertIn("actions: write\n      issues: read", router)
        self.assertIn("on:\n  workflow_call:\n", rc4)
        self.assertIn("on:\n  workflow_call:\n", final)
        self.assertNotIn("issue_comment:", rc4)
        self.assertNotIn("issue_comment:", final)
        self.assertIn("group: ops-rc4-human-approval-promotion-dispatch", rc4)
        self.assertIn("group: ops-final-human-approval-promotion-dispatch", final)
        self.assertIn("cancel-in-progress: false", rc4)
        self.assertIn("cancel-in-progress: false", final)

    def test_called_workflows_preserve_release_and_ga_fail_closed_markers(self) -> None:
        rc4 = RC4.read_text(encoding="utf-8")
        final = FINAL.read_text(encoding="utf-8")
        for required in (
            "ga-windows-authority-rc4-release-lock-promotion.yml",
            "RC4_PROMOTION_DISPATCHED",
            "ga_eligible=false",
        ):
            with self.subTest(rc4_required=required):
                self.assertIn(required, rc4)
        for required in (
            "ga-windows-authority-final-release-lock-promotion.yml",
            "FINAL_REVIEW_BINDING",
            "ga_eligible=false",
        ):
            with self.subTest(final_required=required):
                self.assertIn(required, final)

    def test_policy_authority_tracks_router_topology(self) -> None:
        text = POLICY.read_text(encoding="utf-8")
        allowlist = text.split("allowed_issue_comment_workflows = [", 1)[1].split(
            "          ].sort", 1
        )[0]
        self.assertIn(
            "'.github/workflows/ops-human-approval-promotion-dispatch-router.yml'",
            allowlist,
        )
        self.assertIn(
            "'.github/workflows/ops-external22-ready-to-fresh-readiness.yml'",
            allowlist,
        )
        self.assertNotIn("ops-rc4-human-approval-promotion-dispatch.yml", allowlist)
        self.assertNotIn("ops-final-human-approval-promotion-dispatch.yml", allowlist)

        required = (
            "human_approval_router_contracts_checked = 0",
            "human_approval_router_path = '.github/workflows/ops-human-approval-promotion-dispatch-router.yml'",
            "human_approval_router_contracts_checked += 1",
            "human_approval_router_contracts=1",
            "issue_comment_gate_set=2",
        )
        for value in required:
            with self.subTest(policy_required=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
