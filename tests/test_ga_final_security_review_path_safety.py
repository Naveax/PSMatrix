from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_security_review_packet.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalSecurityReviewPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review = load(SCRIPT, "final_security_review_packet_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def _commitment(self, key_id: str) -> dict[str, object]:
        return {
            "schema": 1,
            "kind": self.review._COMMITMENT_KIND,
            "version": self.review._FINAL_VERSION,
            "reviewed_commit": self.review._FINAL_COMMIT,
            "reviewer": {
                "name": "Independent Reviewer",
                "organization": "External Security Review",
                "role": "Security Reviewer",
                "contact": "reviewer@example.invalid",
                "conflict_of_interest": False,
                "key_controlled_by_reviewer": True,
            },
            "security_review_key_id": key_id,
            "independent_from_release_authority": True,
        }

    @staticmethod
    def _write_public_key(path: Path, public_key) -> None:
        path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def test_read_zip_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-review-zip-symlink-") as temporary:
            root = Path(temporary)
            target = root / "packet-target.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("sentinel.txt", b"sentinel\n")
            link = root / "packet.zip"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "symlink component",
            ):
                self.review._read_zip(link)

    def test_validate_submission_does_not_resolve_packet_symlink_before_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-review-submit-symlink-") as temporary:
            root = Path(temporary)
            target = root / "packet-target.zip"
            with zipfile.ZipFile(target, "w"):
                pass
            link = root / "packet.zip"
            self._symlink_or_skip(link, target)
            report = root / "report.json"
            source = root / "source.zip"
            release = root / "release.json"
            report.write_text("{}\n", encoding="utf-8")
            source.write_bytes(b"source\n")
            release.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "symlink component",
            ):
                self.review.validate_submission(
                    report_path=report,
                    packet_path=link,
                    source_archive=source,
                    release_manifest=release,
                    expected_commit=self.review._FINAL_COMMIT,
                    output=root / "status.json",
                )

    def test_reviewer_commitment_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-commitment-symlink-") as temporary:
            root = Path(temporary)
            target = root / "commitment-target.json"
            target.write_text(
                json.dumps(self._commitment("sha256:" + "0" * 64)) + "\n",
                encoding="utf-8",
            )
            link = root / "commitment.json"
            self._symlink_or_skip(link, target)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "symlink component",
            ):
                self.review._load_reviewer_commitment(
                    link,
                    expected_commit=self.review._FINAL_COMMIT,
                )

    def test_reviewer_public_key_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-key-symlink-") as temporary:
            root = Path(temporary)
            key_target = root / "reviewer-target.public.pem"
            self._write_public_key(key_target, Ed25519PrivateKey.generate().public_key())
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment(self.review.public_key_id(key_target))) + "\n",
                encoding="utf-8",
            )
            key_link = root / "reviewer.public.pem"
            self._symlink_or_skip(key_link, key_target)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "symlink component",
            ):
                self.review.validate_reviewer_authority(
                    commitment_path=commitment,
                    public_key=key_link,
                    expected_commit=self.review._FINAL_COMMIT,
                    output=root / "authority-status.json",
                )

    def test_reviewer_authority_accepts_ed25519_public_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-ed25519-") as temporary:
            root = Path(temporary)
            public_key = root / "reviewer.public.pem"
            self._write_public_key(public_key, Ed25519PrivateKey.generate().public_key())
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment(self.review.public_key_id(public_key))) + "\n",
                encoding="utf-8",
            )
            status = self.review.validate_reviewer_authority(
                commitment_path=commitment,
                public_key=public_key,
                expected_commit=self.review._FINAL_COMMIT,
                output=root / "authority-status.json",
            )
            self.assertEqual(status["security_review_key_algorithm"], "Ed25519")
            self.assertTrue(status["reviewer_public_authority_verified"])
            self.assertFalse(status["private_key_read"])

    def test_reviewer_authority_rejects_non_ed25519_key_even_when_key_id_matches(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-rsa-") as temporary:
            root = Path(temporary)
            public_key = root / "reviewer.public.pem"
            rsa_public = generate_private_key(public_exponent=65537, key_size=2048).public_key()
            self._write_public_key(public_key, rsa_public)
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment(self.review.public_key_id(public_key))) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security reviewer public key must be Ed25519",
            ):
                self.review.validate_reviewer_authority(
                    commitment_path=commitment,
                    public_key=public_key,
                    expected_commit=self.review._FINAL_COMMIT,
                    output=root / "authority-status.json",
                )

    def test_reviewer_commitment_rejects_duplicate_object_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-commitment-duplicate-") as temporary:
            root = Path(temporary)
            commitment = root / "commitment.json"
            first = "sha256:" + "0" * 64
            second = "sha256:" + "1" * 64
            value = json.dumps(self._commitment(first), separators=(",", ":"))
            value = value[:-1] + f',"security_review_key_id":"{second}"' + "}"
            commitment.write_text(value + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "duplicate JSON object key: security_review_key_id",
            ):
                self.review._load_reviewer_commitment(
                    commitment,
                    expected_commit=self.review._FINAL_COMMIT,
                )

    def test_packet_json_entry_rejects_nested_duplicate_object_key(self) -> None:
        entries = {
            self.review._MANIFEST: (
                b'{"schema":1,"source_archive":{"sha256":"first","sha256":"second"}}'
            )
        }
        with self.assertRaisesRegex(
            self.review.FinalSecurityReviewPacketError,
            "duplicate JSON object key: sha256",
        ):
            self.review._json_entry(entries, self.review._MANIFEST)

    def test_completed_report_file_rejects_duplicate_reviewer_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-report-duplicate-") as temporary:
            report = Path(temporary) / "report.json"
            report.write_text(
                '{"reviewer":{"name":"first","name":"second"}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "duplicate JSON object key: name",
            ):
                self.review._strict_json_file(
                    report,
                    label="completed security review report",
                )

    def test_security_review_json_rejects_nonstandard_numeric_constants(self) -> None:
        with self.assertRaisesRegex(
            self.review.FinalSecurityReviewPacketError,
            "non-standard JSON numeric constant: NaN",
        ):
            self.review._strict_json_object(
                b'{"schema":NaN}',
                label="security reviewer commitment",
            )


if __name__ == "__main__":
    unittest.main()
