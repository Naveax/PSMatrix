from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "scripts" / "ga" / "promote_windows_authority_rc4_release_lock.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-lock-promotion.yml"
CANDIDATE = "a" * 40
MARKER = f"RC4 HUMAN REVIEW APPROVED: {CANDIDATE}"
MARKER_SHA256 = hashlib.sha256(MARKER.encode("utf-8")).hexdigest()


def _load_producer():
    spec = importlib.util.spec_from_file_location("rc4_promotion_guard_under_test", PRODUCER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load RC4 promotion producer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RC4PromotionHumanApprovalGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_producer()

    def _proof(self, **overrides):
        values = {
            "candidate_commit": CANDIDATE,
            "review_run_updated_at": "2026-08-21T12:00:00Z",
            "approval_comment_id": "123456789",
            "approval_created_at": "2026-08-21T12:00:01Z",
            "approval_actor": "Naveax",
            "approval_author_association": "OWNER",
            "approval_body_sha256": MARKER_SHA256,
        }
        values.update(overrides)
        return self.module._build_human_review_proof(**values)

    def test_exact_owner_approval_after_review_update_is_bound(self) -> None:
        proof = self._proof()
        self.assertEqual(proof["issue_number"], 260)
        self.assertEqual(proof["comment_id"], 123456789)
        self.assertEqual(proof["actor"], "Naveax")
        self.assertEqual(proof["author_association"], "OWNER")
        self.assertEqual(proof["approval_body_sha256"], MARKER_SHA256)
        self.assertTrue(proof["approval_not_before_review_run_update"])

    def test_approval_before_review_update_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "predates"):
            self._proof(approval_created_at="2026-08-21T11:59:59Z")

    def test_non_owner_or_wrong_actor_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "actor"):
            self._proof(approval_actor="github-actions[bot]")
        with self.assertRaisesRegex(RuntimeError, "OWNER"):
            self._proof(approval_author_association="MEMBER")

    def test_wrong_candidate_marker_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "body SHA-256"):
            self._proof(approval_body_sha256="0" * 64)

    def test_naive_timestamps_and_invalid_comment_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "timezone"):
            self._proof(review_run_updated_at="2026-08-21T12:00:00")
        with self.assertRaisesRegex(RuntimeError, "positive decimal"):
            self._proof(approval_comment_id="0")

    def test_workflow_collects_github_owner_approval_and_passes_it_to_producer(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "issues: read",
            "issues/260/comments?per_page=100&page={page}",
            "item.get('author_association') != 'OWNER'",
            "item.get('body') != marker",
            "created >= review_run_updated",
            "PSMATRIX_RC4_APPROVAL_COMMENT_ID",
            "PSMATRIX_RC4_APPROVAL_BODY_SHA256",
            "--review-run-updated-at",
            "--approval-comment-id",
            "--approval-created-at",
            "--approval-actor",
            "--approval-author-association",
            "--approval-body-sha256",
        )
        for token in required:
            with self.subTest(token=token):
                self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
