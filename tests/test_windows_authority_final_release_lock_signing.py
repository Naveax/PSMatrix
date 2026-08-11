import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair, public_key_id
from psmatrix.util import atomic_write_json


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-lock-signing-control-contract.json"
DRAFT_BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_final_release_lock_draft.py"
PROMOTER = ROOT / "scripts" / "ga" / "promote_windows_authority_final_release_lock.py"
SIGNER = ROOT / "scripts" / "ga" / "sign_windows_authority_final_release.py"
REVIEW_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-lock-review.yml"
PROMOTION_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-lock-promotion.yml"
SIGNING_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-sign-from-lock.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-final-release-lock-signing-source-preflight.yml"
ACTIVE_LOCK = ROOT / "ga-packs" / "03-authoritative-windows" / "final-release-lock.json"
ACTIVE_PUBLIC = ROOT / "release-assets" / "2.0.0" / "psmatrix-2.0.0-release-public.pem"
VERSION = "2.0.0"
PACK = "03-authoritative-windows"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
RC4_AUTHORITY_HEAD = "0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsAuthorityFinalReleaseLockSigningTests(unittest.TestCase):
    def test_control_contract_freezes_final_source_and_rc4_authority_continuity(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-final-release-lock-signing-control-contract")
        self.assertEqual(value["pack"], PACK)
        self.assertEqual(value["version"], VERSION)
        self.assertEqual(value["final_release_commit"], FINAL_COMMIT)
        continuity = value["rc4_authority_continuity"]
        self.assertEqual(continuity["version"], "2.0.0rc4")
        self.assertEqual(continuity["enrollment_control_head"], RC4_AUTHORITY_HEAD)
        self.assertEqual(continuity["workflow"], "production-ga-windows-authority-rc4-release-authority-enrollment")
        self.assertEqual(continuity["artifact"], "psmatrix-2.0.0rc4-release-authority-enrollment")
        self.assertFalse(continuity["authority_rotation_during_final_allowed"])
        self.assertTrue(continuity["same_reviewed_private_authority_required"])
        safety = value["safety"]
        self.assertTrue(safety["review_required_before_promotion"])
        self.assertTrue(safety["reviewed_digests_required_for_promotion"])
        self.assertTrue(safety["repository_commit_required_before_signing"])
        self.assertFalse(safety["private_key_in_repository_allowed"])
        self.assertFalse(safety["sign_without_exact_lock_match_allowed"])
        self.assertFalse(safety["rc4_evidence_may_be_relabelled_as_final"])
        self.assertTrue(safety["final_windows_evidence_rebind_required_after_signing"])
        self.assertFalse(safety["final_ga_evaluator_allowed_during_signing"])

    def test_preparation_branch_contains_no_active_final_lock_or_public_authority(self) -> None:
        self.assertFalse(ACTIVE_LOCK.exists())
        self.assertFalse(ACTIVE_PUBLIC.exists())

    def test_review_and_promotion_workflows_are_private_key_free_and_provenance_bound(self) -> None:
        review = REVIEW_WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "production-ga-windows-authority-final-release-lock-review",
            "production-ga-windows-authority-rc4-release-authority-enrollment",
            "production-ga-windows-authority-final-staging-candidate-selfhosted",
            "psmatrix-2.0.0rc4-release-authority-enrollment",
            "windows-authority-final-unlocked-staging-candidate",
            "build_windows_authority_final_release_lock_draft.py",
            "READY_FOR_HUMAN_REVIEW",
            "final_authority_continuity_review=PASS",
            "active_final_lock_written=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
        ):
            with self.subTest(review=item):
                self.assertIn(item, review)
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "production-ga-windows-authority-final-release-lock-promotion",
            "reviewed_draft_sha256",
            "reviewed_public_key_sha256",
            "production-ga-windows-authority-final-release-lock-review",
            "psmatrix-2.0.0-final-release-lock-review",
            "promote_windows_authority_final_release_lock.py",
            "READY_FOR_EXACT_REPOSITORY_COMMIT",
            "repository_mutated=false",
            "psmatrix-2.0.0-final-release-lock-promotion-candidate",
        ):
            with self.subTest(promotion=item):
                self.assertIn(item, promotion)
        for text in (review, promotion):
            for forbidden in ("PSMATRIX_RELEASE_PRIVATE_KEY", "secrets.", "contents: write", "git push", "gh pr"):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, text)

    def test_protected_signing_secret_is_single_step_after_all_provenance_checks(self) -> None:
        text = SIGNING_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-final-release-sign-from-lock",
            "environment: production-ga-release-signing",
            "committed final release lock is missing",
            "committed final release public authority is missing",
            "Validate all four frozen upstream workflow runs and artifacts",
            "Revalidate exact locked final staging bytes before secret access",
            "Materialize protected final release private key",
            "RELEASE_PRIVATE_KEY: ${{ secrets.PSMATRIX_RELEASE_PRIVATE_KEY }}",
            "Sign exact committed final release lock",
            "sign_windows_authority_final_release.py",
            "Remove protected final release private key",
            "independent_final_release_verification=PASS",
            "private_key_free_final_protected_release=PASS",
            "release_artifacts_signed=true",
            "final_windows_evidence_rebound=false",
            "final_ga_evaluator_invoked=false",
            "authoritative=false",
            "ga_eligible=false",
            "psmatrix-2.0.0-protected-release",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_RELEASE_PRIVATE_KEY"), 1)
        provenance = text.index("Validate all four frozen upstream workflow runs and artifacts")
        revalidate = text.index("Revalidate exact locked final staging bytes before secret access")
        secret = text.index("Materialize protected final release private key")
        sign = text.index("Sign exact committed final release lock")
        remove = text.index("Remove protected final release private key")
        self.assertLess(provenance, secret)
        self.assertLess(revalidate, secret)
        self.assertLess(secret, sign)
        self.assertLess(sign, remove)
        self.assertNotIn("python -m psmatrix.cli ga evaluate", text)

    def test_scripts_keep_final_signing_separate_from_windows_authority_and_ga(self) -> None:
        draft = DRAFT_BUILDER.read_text(encoding="utf-8")
        promoter = PROMOTER.read_text(encoding="utf-8")
        signer = SIGNER.read_text(encoding="utf-8")
        for item in (
            '"authority_reused_for_final_release": True',
            '"authority_rotated_during_final_release": False',
            '"rc4_evidence_may_be_relabelled_as_final": False',
            '"final_windows_evidence_rebound": False',
            '"final_ga_evaluator_invoked": False',
            '"authoritative": False',
            '"ga_eligible": False',
        ):
            with self.subTest(draft=item):
                self.assertIn(item, draft)
        for item in (
            '"READY_FOR_EXACT_REPOSITORY_COMMIT"',
            '"repository_mutated": False',
            '"release_artifacts_signed": False',
            '"final_windows_evidence_rebound": False',
            '"final_ga_evaluator_invoked": False',
            '"authoritative": False',
            '"ga_eligible": False',
        ):
            with self.subTest(promoter=item):
                self.assertIn(item, promoter)
        for item in (
            '_VERSION = "2.0.0"',
            "Protected final release private key does not match the locked authority",
            '"release_artifacts_signed": True',
            '"authority_continuity_from_rc4_verified": True',
            '"release_authority_rotated_during_final_signing": False',
            '"rc4_evidence_relabelled_as_final": False',
            '"final_windows_evidence_rebound": False',
            '"final_ga_evaluator_invoked": False',
            '"authoritative": False',
            '"ga_eligible": False',
        ):
            with self.subTest(signer=item):
                self.assertIn(item, signer)
        self.assertNotIn("2.0.0rc[0-9]", signer)
        self.assertNotIn("python -m psmatrix.cli ga evaluate", signer)

    def test_final_promoter_runtime_produces_private_key_free_commit_candidate(self) -> None:
        promoter = _load(PROMOTER, "psmatrix_final_promoter_test")
        candidate = FINAL_COMMIT
        control = "b" * 40
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-promotion-runtime-") as temp:
            root = Path(temp)
            review = root / "review"
            output = root / "promotion"
            keys = root / "keys"
            public_dir = review / "release-assets" / VERSION
            review.mkdir()
            public_dir.mkdir(parents=True)
            keys.mkdir()
            private_key = keys / "release.private.pem"
            public_key = keys / "release.public.pem"
            generate_ed25519_keypair(private_key, public_key)
            reviewed_public = public_dir / f"psmatrix-{VERSION}-release-public.pem"
            reviewed_public.write_bytes(public_key.read_bytes())
            public_sha = _sha256(reviewed_public)
            key_id = public_key_id(reviewed_public)
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
                "final_release_commit": candidate,
                "rc4_authority_enrollment": {
                    "run_id": "2001",
                    "control_head": RC4_AUTHORITY_HEAD,
                    "workflow": "production-ga-windows-authority-rc4-release-authority-enrollment",
                    "artifact": "psmatrix-2.0.0rc4-release-authority-enrollment",
                },
                "unsigned_final_staging": {
                    "run_id": "2002",
                    "control_head": candidate,
                    "workflow": "production-ga-windows-authority-final-staging-candidate-selfhosted",
                    "artifact": "windows-authority-final-unlocked-staging-candidate",
                },
            }
            draft = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-final-release-staging-lock",
                "pack": PACK,
                "version": VERSION,
                "release_commit": candidate,
                "source_date_epoch": 0,
                "release_public_key": {"path": f"release-assets/{VERSION}/psmatrix-{VERSION}-release-public.pem", "sha256": public_sha, "key_id": key_id},
                "artifacts": artifacts,
                "source_runs": source_runs,
                "authority_continuity": {
                    "source_version": "2.0.0rc4",
                    "source_enrollment_control_head": RC4_AUTHORITY_HEAD,
                    "source_enrollment_run_id": "2001",
                    "public_key_sha256": public_sha,
                    "key_id": key_id,
                    "same_reviewed_private_authority_required": True,
                    "authority_reused_for_final_release": True,
                    "authority_rotated_during_final_release": False,
                    "review_required": True,
                },
                "safety": {
                    "authority_rotation_during_final_allowed": False,
                    "private_key_in_repository_allowed": False,
                    "sign_without_exact_lock_match_allowed": False,
                    "rc4_evidence_may_be_relabelled_as_final": False,
                    "final_windows_evidence_rebind_required_after_signing": True,
                    "final_ga_evaluator_allowed_during_signing": False,
                },
                "review_state": "DRAFT_REQUIRES_HUMAN_REVIEW",
                "active_lock_written": False,
                "release_artifacts_signed": False,
                "final_windows_evidence_rebound": False,
                "final_ga_evaluator_invoked": False,
                "authoritative": False,
                "ga_eligible": False,
            }
            draft_path = review / "final-release-lock.review-draft.json"
            atomic_write_json(draft_path, draft)
            atomic_write_json(
                review / "final-release-lock-review.json",
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-final-release-lock-review-bundle",
                    "status": "READY_FOR_HUMAN_REVIEW",
                    "version": VERSION,
                    "final_candidate_commit": candidate,
                    "source_runs": source_runs,
                    "private_key_material_absent": True,
                    "active_lock_written": False,
                    "release_artifacts_signed": False,
                    "final_windows_evidence_rebound": False,
                    "final_ga_evaluator_invoked": False,
                    "authoritative": False,
                    "ga_eligible": False,
                },
            )
            result = promoter.promote(
                review_root=review,
                output_root=output,
                final_candidate_commit=candidate,
                promotion_control_head=control,
                promotion_run_id="2004",
                review_run_id="2003",
                reviewed_draft_sha256=_sha256(draft_path),
                reviewed_public_key_sha256=public_sha,
            )
            self.assertEqual(result["status"], "READY_FOR_EXACT_REPOSITORY_COMMIT")
            self.assertFalse(result["repository_mutated"])
            active = json.loads((output / "ga-packs" / PACK / "final-release-lock.json").read_text(encoding="utf-8"))
            self.assertEqual(active["release_commit"], candidate)
            self.assertEqual(active["promotion_evidence"]["promotion_run_id"], "2004")
            self.assertTrue(active["promotion_evidence"]["human_review_bound"])
            self.assertFalse(active["release_artifacts_signed"])
            for path in output.rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"-----BEGIN PRIVATE KEY-----", path.read_bytes())

    def test_final_signer_runtime_requires_exact_lock_authority_and_stays_non_authoritative(self) -> None:
        signer = _load(SIGNER, "psmatrix_final_signer_test")
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-signer-runtime-") as temp:
            root = Path(temp)
            staging = root / "staging"
            output = root / "signed"
            keys = root / "keys"
            staging.mkdir()
            keys.mkdir()
            private_key = keys / "release.private.pem"
            public_key = keys / "release.public.pem"
            generate_ed25519_keypair(private_key, public_key)
            public_sha = _sha256(public_key)
            key_id = public_key_id(public_key)
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
                path.write_bytes(f"final-runtime-{index}-{suffix}\n".encode())
                paths.append(path)
                artifacts.append({"name": path.name, "sha256": _sha256(path), "size": path.stat().st_size})
            create_release_manifest(paths, staging / f"psmatrix-{VERSION}-release-unsigned.json", version=VERSION)
            atomic_write_json(
                staging / f"psmatrix-{VERSION}-windows-authority-final-staging.json",
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-final-release-candidate-staging",
                    "status": "READY_FOR_FINAL_RELEASE_LOCK_REVIEW",
                    "version": VERSION,
                    "release_commit": FINAL_COMMIT,
                    "rc4_anchor_is_ancestor": True,
                    "artifacts": artifacts,
                    "private_key_read": False,
                    "release_artifacts_signed": False,
                    "final_release_lock_written": False,
                    "final_windows_evidence_rebound": False,
                    "final_ga_evaluator_invoked": False,
                    "rc4_evidence_relabelled_as_final": False,
                    "downloads_files": False,
                    "extracts_existing_operation_package": False,
                    "authoritative": False,
                    "ga_eligible": False,
                },
            )
            lock_path = root / "final-release-lock.json"
            atomic_write_json(
                lock_path,
                {
                    "schema": 1,
                    "kind": "psmatrix.windows-authority-final-release-staging-lock",
                    "pack": PACK,
                    "version": VERSION,
                    "release_commit": FINAL_COMMIT,
                    "release_public_key": {"path": f"release-assets/{VERSION}/psmatrix-{VERSION}-release-public.pem", "sha256": public_sha, "key_id": key_id},
                    "artifacts": artifacts,
                    "authority_continuity": {
                        "source_version": "2.0.0rc4",
                        "public_key_sha256": public_sha,
                        "key_id": key_id,
                        "same_reviewed_private_authority_required": True,
                        "authority_reused_for_final_release": True,
                        "authority_rotated_during_final_release": False,
                    },
                    "safety": {
                        "authority_rotation_during_final_allowed": False,
                        "private_key_in_repository_allowed": False,
                        "sign_without_exact_lock_match_allowed": False,
                        "rc4_evidence_may_be_relabelled_as_final": False,
                        "final_windows_evidence_rebind_required_after_signing": True,
                        "final_ga_evaluator_allowed_during_signing": False,
                    },
                    "promotion_state": "READY_FOR_EXACT_REPOSITORY_COMMIT",
                    "promotion_evidence": {"human_review_bound": True, "repository_commit_required": True},
                    "release_artifacts_signed": False,
                    "final_windows_evidence_rebound": False,
                    "final_ga_evaluator_invoked": False,
                    "authoritative": False,
                    "ga_eligible": False,
                },
            )
            valid = {"valid": True}
            with patch.object(signer, "_git_text", side_effect=lambda source, *args: FINAL_COMMIT if args == ("rev-parse", "HEAD") else ""), patch.object(
                signer, "verify_windows_worker_package", return_value=valid
            ), patch.object(signer, "verify_certification_kit", return_value=valid), patch.object(
                signer, "verify_provisioning_kit", return_value=valid
            ):
                status = signer.sign(
                    source_root=ROOT,
                    staging_root=staging,
                    release_lock=lock_path,
                    release_private_key=private_key,
                    release_public_key=public_key,
                    output_root=output,
                )
            self.assertEqual(status["status"], "PASS")
            self.assertTrue(status["release_artifacts_signed"])
            self.assertTrue(status["authority_continuity_from_rc4_verified"])
            self.assertFalse(status["release_authority_rotated_during_final_signing"])
            self.assertFalse(status["final_windows_evidence_rebound"])
            self.assertFalse(status["final_ga_evaluator_invoked"])
            self.assertFalse(status["authoritative"])
            self.assertFalse(status["ga_eligible"])

            wrong_private = keys / "wrong.private.pem"
            wrong_public = keys / "wrong.public.pem"
            generate_ed25519_keypair(wrong_private, wrong_public)
            bad_output = root / "bad-signed"
            with patch.object(signer, "_git_text", side_effect=lambda source, *args: FINAL_COMMIT if args == ("rev-parse", "HEAD") else ""), self.assertRaisesRegex(
                RuntimeError, "does not match the locked authority"
            ):
                signer.sign(
                    source_root=ROOT,
                    staging_root=staging,
                    release_lock=lock_path,
                    release_private_key=wrong_private,
                    release_public_key=public_key,
                    output_root=bad_output,
                )

    def test_source_preflight_tracks_exact_control_boundary(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-windows-authority-final-release-lock-signing-source-preflight",
            "final-release-lock-signing-control-contract.json",
            "build_windows_authority_final_release_lock_draft.py",
            "promote_windows_authority_final_release_lock.py",
            "sign_windows_authority_final_release.py",
            "ga-windows-authority-final-release-lock-review.yml",
            "ga-windows-authority-final-release-lock-promotion.yml",
            "ga-windows-authority-final-release-sign-from-lock.yml",
            "tests.test_windows_authority_final_release_lock_signing",
            "final_lock_signing_source_contract=PASS",
            "active_final_lock_present=false",
            "final_release_artifacts_signed=false",
            "final_windows_evidence_rebound=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
