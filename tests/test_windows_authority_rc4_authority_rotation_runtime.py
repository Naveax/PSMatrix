import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENROLL_SCRIPT = ROOT / "scripts" / "ga" / "enroll_windows_authority_release_authority.py"
LOCK_DRAFT_SCRIPT = ROOT / "scripts" / "ga" / "build_windows_authority_release_lock_draft.py"
PREVIOUS_PUBLIC_KEY = ROOT / "release-assets" / "2.0.0rc2" / "psmatrix-2.0.0rc2-release-public.pem"
VERSION = "2.0.0rc4"
CANDIDATE_COMMIT = "a" * 40


class WindowsAuthorityRC4AuthorityRotationRuntimeTests(unittest.TestCase):
    def test_enrollment_and_review_lock_runtime_is_private_key_free_and_provenance_bound(self) -> None:
        from psmatrix.signing import generate_ed25519_keypair

        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-rotation-runtime-") as temporary:
            root = Path(temporary)
            private_key = root / "protected" / "release.private.pem"
            generated_public = root / "protected" / "release.public.pem"
            enrollment = root / "enrollment"
            staging = root / "staging"
            review = root / "review"
            private_key.parent.mkdir(parents=True, exist_ok=True)
            staging.mkdir(parents=True, exist_ok=True)

            generate_ed25519_keypair(private_key, generated_public)
            self.assertTrue(private_key.is_file())
            self.assertTrue(generated_public.is_file())

            enrolled = subprocess.run(
                [
                    sys.executable,
                    str(ENROLL_SCRIPT),
                    "--private-key",
                    str(private_key),
                    "--previous-public-key",
                    str(PREVIOUS_PUBLIC_KEY),
                    "--output-root",
                    str(enrollment),
                    "--version",
                    VERSION,
                    "--candidate-commit",
                    CANDIDATE_COMMIT,
                    "--rotation-reason",
                    "lost_previous_private_authority",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(enrolled.returncode, 0, enrolled.stdout + enrolled.stderr)

            enrollment_report_path = enrollment / f"psmatrix-{VERSION}-release-authority-enrollment.json"
            proposed_public = enrollment / f"psmatrix-{VERSION}-release-public.pem"
            self.assertTrue(enrollment_report_path.is_file())
            self.assertTrue(proposed_public.is_file())
            enrollment_report = json.loads(enrollment_report_path.read_text(encoding="utf-8"))
            self.assertEqual(enrollment_report["status"], "READY_FOR_PUBLIC_AUTHORITY_REVIEW")
            self.assertEqual(enrollment_report["candidate_commit"], CANDIDATE_COMMIT)
            self.assertFalse(enrollment_report["private_key_published"])
            self.assertFalse(enrollment_report["release_artifacts_signed"])
            self.assertNotEqual(
                enrollment_report["previous_authority"]["key_id"],
                enrollment_report["proposed_authority"]["key_id"],
            )

            private_markers = (
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN OPENSSH PRIVATE KEY-----",
            )
            for path in enrollment.rglob("*"):
                if path.is_file():
                    self.assertFalse(any(marker in path.read_bytes() for marker in private_markers), path.name)

            suffixes = (
                "-py3-none-any.whl",
                "-source.tar.gz",
                "-source.zip",
                "-windows-certification-kit.zip",
                "-windows-provisioning-kit.zip",
                "-windows-workers.zip",
            )
            artifacts = []
            for index, suffix in enumerate(suffixes, start=1):
                path = staging / f"psmatrix-{VERSION}{suffix}"
                payload = f"rc4-runtime-artifact-{index}:{suffix}\n".encode("utf-8")
                path.write_bytes(payload)
                artifacts.append(
                    {
                        "name": path.name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                )

            staging_report = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-release-candidate-staging",
                "status": "READY_FOR_PROTECTED_SIGNING",
                "version": VERSION,
                "release_commit": CANDIDATE_COMMIT,
                "artifacts": artifacts,
                "reproducibility": {
                    "wheel": {"reproducible": True},
                    "source_zip": {"reproducible": True},
                    "source_tar_gz": {"reproducible": True},
                    "windows_workers": {"reproducible": True},
                    "windows_certification_kit": {"reproducible": True},
                    "windows_provisioning_kit": {"reproducible": True},
                },
                "verification": {
                    "windows_workers": {"valid": True},
                    "windows_certification_kit": {"valid": True},
                    "windows_provisioning_kit": {"valid": True},
                },
                "private_key_read": False,
                "signed_release_manifest_written": False,
                "downloads_files": False,
                "extracts_existing_operation_package": False,
                "authoritative": False,
                "ga_eligible": False,
            }
            (staging / f"psmatrix-{VERSION}-windows-authority-staging.json").write_text(
                json.dumps(staging_report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            drafted = subprocess.run(
                [
                    sys.executable,
                    str(LOCK_DRAFT_SCRIPT),
                    "--staging-root",
                    str(staging),
                    "--enrollment-root",
                    str(enrollment),
                    "--previous-public-key",
                    str(PREVIOUS_PUBLIC_KEY),
                    "--output-root",
                    str(review),
                    "--candidate-commit",
                    CANDIDATE_COMMIT,
                    "--enrollment-run-id",
                    "1001",
                    "--staging-run-id",
                    "1002",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(drafted.returncode, 0, drafted.stdout + drafted.stderr)

            draft = json.loads((review / "rc4-release-lock.review-draft.json").read_text(encoding="utf-8"))
            review_report = json.loads((review / "rc4-release-lock-review.json").read_text(encoding="utf-8"))
            self.assertEqual(draft["review_state"], "DRAFT_REQUIRES_HUMAN_REVIEW")
            self.assertFalse(draft["active_lock_written"])
            self.assertFalse(draft["release_artifacts_signed"])
            self.assertEqual(draft["source_runs"]["control_head"], CANDIDATE_COMMIT)
            self.assertEqual(draft["source_runs"]["authority_enrollment"]["run_id"], "1001")
            self.assertEqual(draft["source_runs"]["unsigned_staging"]["run_id"], "1002")
            self.assertEqual(review_report["status"], "READY_FOR_HUMAN_REVIEW")
            self.assertEqual(review_report["source_runs"], draft["source_runs"])
            self.assertFalse((review / "rc4-release-lock.json").exists())

            copied_public = review / "release-assets" / VERSION / f"psmatrix-{VERSION}-release-public.pem"
            self.assertTrue(copied_public.is_file())
            self.assertEqual(copied_public.read_bytes(), proposed_public.read_bytes())
            for path in review.rglob("*"):
                if path.is_file():
                    self.assertFalse(any(marker in path.read_bytes() for marker in private_markers), path.name)


if __name__ == "__main__":
    unittest.main()
