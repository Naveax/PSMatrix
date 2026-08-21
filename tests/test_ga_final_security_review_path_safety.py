from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
                "security review packet is missing or unsafe",
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
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security review packet is missing or unsafe",
            ):
                self.review.validate_submission(
                    report_path=root / "missing-report.json",
                    packet_path=link,
                    source_archive=root / "missing-source.zip",
                    release_manifest=root / "missing-release.json",
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
                "security reviewer commitment is missing or unsafe",
            ):
                self.review._load_reviewer_commitment(
                    link,
                    expected_commit=self.review._FINAL_COMMIT,
                )

    def test_reviewer_public_key_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-reviewer-key-symlink-") as temporary:
            root = Path(temporary)
            key_target = root / "reviewer-target.public.pem"
            public_key = Ed25519PrivateKey.generate().public_key()
            key_target.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment(self.review.public_key_id(key_target))) + "\n",
                encoding="utf-8",
            )
            key_link = root / "reviewer.public.pem"
            self._symlink_or_skip(key_link, key_target)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security reviewer public key is missing or unsafe",
            ):
                self.review.validate_reviewer_authority(
                    commitment_path=commitment,
                    public_key=key_link,
                    expected_commit=self.review._FINAL_COMMIT,
                    output=root / "authority-status.json",
                )


if __name__ == "__main__":
    unittest.main()
