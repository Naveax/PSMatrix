import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair, public_key_id
from psmatrix.util import atomic_write_json


ROOT = Path(__file__).resolve().parents[1]
PROMOTER_PATH = ROOT / "scripts" / "ga" / "promote_windows_authority_rc4_release_lock.py"
SIGNER_PATH = ROOT / "scripts" / "ga" / "sign_windows_authority_release_candidate.py"
PROMOTION_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-lock-promotion.yml"
SIGNING_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-sign-from-lock.yml"
ACTIVE_LOCK = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-release-lock.json"
ACTIVE_PUBLIC = ROOT / "release-assets" / "2.0.0rc4" / "psmatrix-2.0.0rc4-release-public.pem"
VERSION = "2.0.0rc4"
PACK = "03-authoritative-windows"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip().lower()


class WindowsAuthorityRC4LockPromotionSigningTests(unittest.TestCase):
    def test_preparation_branch_does_not_smuggle_an_active_lock_or_public_key(self) -> None:
        self.assertFalse(ACTIVE_LOCK.exists())
        self.assertFalse(ACTIVE_PUBLIC.exists())

    def test_promotion_workflow_is_read_only_review_bound_and_private_key_free(self) -> None:
        text = PROMOTION_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-rc4-release-lock-promotion",
            "reviewed_draft_sha256",
            "reviewed_public_key_sha256",
            "promotion_control_head",
            "PROMOTION_RUN_ID: ${{ github.run_id }}",
            "production-ga-windows-authority-rc4-release-lock-review",
            "psmatrix-2.0.0rc4-release-lock-review",
            "promote_windows_authority_rc4_release_lock.py",
            "READY_FOR_EXACT_REPOSITORY_COMMIT",
            "repository_mutated=false",
            "release_artifacts_signed=false",
            "psmatrix-2.0.0rc4-release-lock-promotion-candidate",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "secrets.",
            "contents: write",
            "git push",
            "gh pr",
            "create_ref",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_promotion_builder_freezes_review_and_promotion_provenance(self) -> None:
        text = PROMOTER_PATH.read_text(encoding="utf-8")
        required = (
            '"READY_FOR_EXACT_REPOSITORY_COMMIT"',
            '"promotion_run_id": promotion_run_id',
            '"promotion_control_head": promotion_control_head',
            '"review_run_id": review_run_id',
            '"reviewed_draft_sha256": reviewed_draft_sha256',
            '"reviewed_public_key_sha256": reviewed_public_key_sha256',
            '"human_review_bound": True',
            '"promotion_candidate_only": True',
            '"repository_commit_required": True',
            '"repository_mutated": False',
            '"release_artifacts_signed": False',
            '"authoritative": False',
            '"ga_eligible": False',
            'output / "ga-packs" / _PACK / "rc4-release-lock.json"',
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn("sign_bytes", text)
        self.assertNotIn("generate_ed25519_keypair", text)

    def test_protected_signer_requires_committed_lock_and_four_run_provenance(self) -> None:
        text = SIGNING_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-rc4-release-sign-from-lock",
            "environment: production-ga-release-signing",
            "lock_control_head",
            "candidate_commit",
            "enrollment_run_id",
            "staging_run_id",
            "review_run_id",
            "promotion_run_id",
            "ga-packs/03-authoritative-windows/rc4-release-lock.json",
            "committed RC4 release lock is missing",
            "production-ga-windows-authority-rc4-release-authority-enrollment",
            "production-ga-windows-authority-rc4-staging-candidate-selfhosted",
            "production-ga-windows-authority-rc4-release-lock-review",
            "production-ga-windows-authority-rc4-release-lock-promotion",
            "release-assets/2.0.0rc4/psmatrix-2.0.0rc4-release-public.pem",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "sign_windows_authority_release_candidate.py",
            "Remove protected RC4 release private key",
            "independent_rc4_release_verification=PASS",
            "private_key_free_rc4_protected_release=PASS",
            "psmatrix-2.0.0rc4-protected-release",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertEqual(text.count("secrets.PSMATRIX_RELEASE_PRIVATE_KEY"), 1)
        secret_step = text.index("Materialize protected RC4 release private key")
        provenance_step = text.index("Validate all four frozen workflow runs and artifacts")
        sign_step = text.index("Sign exact committed RC4 lock")
        remove_step = text.index("Remove protected RC4 release private key")
        self.assertLess(provenance_step, secret_step)
        self.assertLess(secret_step, sign_step)
        self.assertLess(sign_step, remove_step)

    def test_signer_does_not_claim_windows_ga_authority(self) -> None:
        text = SIGNING_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("'authoritative': False", text)
        self.assertIn("'ga_eligible': False", text)
        self.assertIn("authority_rotation_reviewed", text)
        self.assertIn("release_authority_rotated_during_signing", text)
        self.assertNotIn("'authoritative': True", text)
        self.assertNotIn("'ga_eligible': True", text)

    def test_promotion_runtime_produces_exact_private_key_free_commit_candidate(self) -> None:
        promoter = _load(PROMOTER_PATH, "psmatrix_rc4_promoter_test")
        candidate = "a" * 40
        control = "b" * 40
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-promotion-runtime-") as temp:
            root = Path(temp)
            protected = root / "protected"
            review = root / "review"
            output = root / "promotion"
            protected.mkdir()
            public_dir = review / "release-assets" / VERSION
            public_dir.mkdir(parents=True)
            private_key = protected / "release.private.pem"
            public_key = protected / "release.public.pem"
            generate_ed25519_keypair(private_key, public_key)
            proposed_public = public_dir / f"psmatrix-{VERSION}-release-public.pem"
            proposed_public.write_bytes(public_key.read_bytes())
            public_sha = _sha256(proposed_public)
            proposed_id = public_key_id(proposed_public)

            artifacts = [
                {"name": f"psmatrix-{VERSION}{suffix}", "sha256": hashlib.sha256(suffix.encode()).hexdigest(), "size": 10 + index}
                for index, suffix in enumerate((
                    "-py3-none-any.whl",
                    "-source.tar.gz",
                    "-source.zip",
                    "-windows-certification-kit.zip",
                    "-windows-provisioning-kit.zip",
                    "-windows-workers.zip",
                ), start=1)
            ]
            source_runs = {
                "control_head": candidate,
                "authority_enrollment": {
                    "run_id": "1001",
                    "workflow": "production-ga-windows-authority-rc4-release-authority-enrollment",
                    "artifact": f"psmatrix-{VERSION}-release-authority-enrollment",
                },
                "unsigned_staging": {
                    "run_id": "1002",
                    "workflow": "production-ga-windows-authority-rc4-staging-candidate-selfhosted",
                    "artifact": "windows-authority-rc4-unlocked-staging-candidate",
                },
            }
            draft = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-release-staging-lock",
                "pack": PACK,
                "version": VERSION,
                "release_commit": candidate,
                "source_date_epoch": 0,
                "release_public_key": {"path": f"release-assets/{VERSION}/psmatrix-{VERSION}-release-public.pem", "sha256": public_sha},
                "artifacts": artifacts,
                "source_runs": source_runs,
                "review_evidence": {"builder_status": "READY_FOR_PROTECTED_SIGNING"},
                "authority_rotation": {
                    "reason": "lost_previous_private_authority",
                    "previous_public_key_sha256": "1" * 64,
                    "previous_key_id": "previous",
                    "proposed_public_key_sha256": public_sha,
                    "proposed_key_id": proposed_id,
                    "existing_candidate_mutated": False,
                    "new_candidate": True,
                    "review_required": True,
                },
                "safety": {
                    "stale_rc2_operation_package_allowed": False,
                    "release_authority_rotation_allowed": False,
                    "private_key_in_repository_allowed": False,
                    "sign_without_exact_hash_match_allowed": False,
                },
                "review_state": "DRAFT_REQUIRES_HUMAN_REVIEW",
                "active_lock_written": False,
                "release_artifacts_signed": False,
                "authoritative": False,
                "ga_eligible": False,
            }
            draft_path = review / "rc4-release-lock.review-draft.json"
            atomic_write_json(draft_path, draft)
            atomic_write_json(
                review / "rc4-release-lock-review.json",
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-release-lock-review-bundle",
                    "status": "READY_FOR_HUMAN_REVIEW",
                    "version": VERSION,
                    "candidate_commit": candidate,
                    "source_runs": source_runs,
                    "private_key_material_absent": True,
                    "active_lock_written": False,
                    "release_artifacts_signed": False,
                },
            )
            approval_body_sha256 = hashlib.sha256(
                f"RC4 HUMAN REVIEW APPROVED: {candidate}".encode("utf-8")
            ).hexdigest()
            result = promoter.promote(
                review_root=review,
                output_root=output,
                candidate_commit=candidate,
                promotion_control_head=control,
                promotion_run_id="1004",
                review_run_id="1003",
                reviewed_draft_sha256=_sha256(draft_path),
                reviewed_public_key_sha256=public_sha,
                review_run_updated_at="2026-08-21T12:00:00Z",
                approval_comment_id="2001",
                approval_created_at="2026-08-21T12:00:01Z",
                approval_actor="Naveax",
                approval_author_association="OWNER",
                approval_body_sha256=approval_body_sha256,
            )
            self.assertEqual(result["status"], "READY_FOR_EXACT_REPOSITORY_COMMIT")
            self.assertFalse(result["repository_mutated"])
            self.assertFalse(result["release_artifacts_signed"])
            active = json.loads((output / "ga-packs" / PACK / "rc4-release-lock.json").read_text(encoding="utf-8"))
            self.assertEqual(active["promotion_evidence"]["promotion_run_id"], "1004")
            self.assertEqual(active["promotion_evidence"]["review_run_id"], "1003")
            self.assertEqual(active["promotion_evidence"]["promotion_control_head"], control)
            self.assertTrue(active["promotion_evidence"]["human_review_bound"])
            self.assertEqual(
                active["promotion_evidence"]["human_review"]["comment_id"], 2001
            )
            self.assertEqual(
                active["promotion_evidence"]["human_review"]["approval_body_sha256"],
                approval_body_sha256,
            )
            self.assertTrue(active["promotion_evidence"]["repository_commit_required"])
            self.assertFalse(active["release_artifacts_signed"])
            for path in output.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    self.assertNotIn(b"-----BEGIN PRIVATE KEY-----", data)

            bad = root / "bad-promotion"
            with self.assertRaisesRegex(RuntimeError, "operator-reviewed digest"):
                promoter.promote(
                    review_root=review,
                    output_root=bad,
                    candidate_commit=candidate,
                    promotion_control_head=control,
                    promotion_run_id="1005",
                    review_run_id="1003",
                    reviewed_draft_sha256="0" * 64,
                    reviewed_public_key_sha256=public_sha,
                    review_run_updated_at="2026-08-21T12:00:00Z",
                    approval_comment_id="2001",
                    approval_created_at="2026-08-21T12:00:01Z",
                    approval_actor="Naveax",
                    approval_author_association="OWNER",
                    approval_body_sha256=approval_body_sha256,
                )

    def test_generic_signer_runtime_honors_exact_lock_and_key(self) -> None:
        signer = _load(SIGNER_PATH, "psmatrix_rc4_signer_test")
        commit = _head()
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-signer-runtime-") as temp:
            root = Path(temp)
            staging = root / "staging"
            output = root / "signed"
            keys = root / "keys"
            staging.mkdir()
            keys.mkdir()
            private_key = keys / "release.private.pem"
            public_key = keys / "release.public.pem"
            generate_ed25519_keypair(private_key, public_key)
            artifacts = []
            paths = []
            for index, suffix in enumerate((
                "-py3-none-any.whl",
                "-source.tar.gz",
                "-source.zip",
                "-windows-certification-kit.zip",
                "-windows-provisioning-kit.zip",
                "-windows-workers.zip",
            ), start=1):
                path = staging / f"psmatrix-{VERSION}{suffix}"
                path.write_bytes(f"runtime-{index}-{suffix}\n".encode())
                paths.append(path)
                artifacts.append({"name": path.name, "sha256": _sha256(path), "size": path.stat().st_size})
            create_release_manifest(paths, staging / f"psmatrix-{VERSION}-release-unsigned.json", version=VERSION)
            atomic_write_json(
                staging / f"psmatrix-{VERSION}-windows-authority-staging.json",
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-release-candidate-staging",
                    "status": "READY_FOR_PROTECTED_SIGNING",
                    "version": VERSION,
                    "release_commit": commit,
                    "artifacts": artifacts,
                    "private_key_read": False,
                    "signed_release_manifest_written": False,
                    "downloads_files": False,
                    "extracts_existing_operation_package": False,
                    "authoritative": False,
                    "ga_eligible": False,
                },
            )
            lock_path = root / "rc4-release-lock.json"
            atomic_write_json(
                lock_path,
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-release-staging-lock",
                    "pack": PACK,
                    "version": VERSION,
                    "release_commit": commit,
                    "release_public_key": {"path": "irrelevant-in-direct-test", "sha256": _sha256(public_key)},
                    "artifacts": artifacts,
                },
            )
            valid = {"valid": True}
            with patch.object(signer, "verify_windows_worker_package", return_value=valid), patch.object(
                signer, "verify_certification_kit", return_value=valid
            ), patch.object(signer, "verify_provisioning_kit", return_value=valid):
                status = signer.sign(
                    source_root=ROOT,
                    staging_root=staging,
                    release_lock=lock_path,
                    release_private_key=private_key,
                    release_public_key=public_key,
                    output_root=output,
                )
            self.assertEqual(status["status"], "PASS")
            self.assertTrue(status["release_private_key_matches_locked_authority"])
            self.assertTrue(status["signed_release_manifest_verified"])
            self.assertFalse(status["private_key_copied_to_output"])
            for path in output.rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"-----BEGIN PRIVATE KEY-----", path.read_bytes())

            wrong_private = keys / "wrong.private.pem"
            wrong_public = keys / "wrong.public.pem"
            generate_ed25519_keypair(wrong_private, wrong_public)
            bad_output = root / "bad-signed"
            with patch.object(signer, "verify_windows_worker_package", return_value=valid), patch.object(
                signer, "verify_certification_kit", return_value=valid
            ), patch.object(signer, "verify_provisioning_kit", return_value=valid):
                with self.assertRaisesRegex(RuntimeError, "does not match the locked release authority"):
                    signer.sign(
                        source_root=ROOT,
                        staging_root=staging,
                        release_lock=lock_path,
                        release_private_key=wrong_private,
                        release_public_key=public_key,
                        output_root=bad_output,
                    )


if __name__ == "__main__":
    unittest.main()
