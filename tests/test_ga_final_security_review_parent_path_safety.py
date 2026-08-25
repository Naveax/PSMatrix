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
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-security-vulnerability-evidence-producer-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-security-vulnerability-evidence-producers-source-preflight.yml"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalSecurityReviewParentPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review = load(SCRIPT, "final_security_review_parent_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
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

    def test_read_zip_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-parent-zip-") as temporary:
            root = Path(temporary)
            target_dir = root / "packet-target"
            target_dir.mkdir()
            packet = target_dir / "packet.zip"
            with zipfile.ZipFile(packet, "w") as archive:
                archive.writestr("sentinel.txt", b"sentinel\n")
            alias_dir = root / "packet-alias"
            self._symlink_or_skip(alias_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security review packet contains a symlink component",
            ):
                self.review._read_zip(alias_dir / "packet.zip")

    def test_commitment_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-parent-commitment-") as temporary:
            root = Path(temporary)
            target_dir = root / "commitment-target"
            target_dir.mkdir()
            commitment = target_dir / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment("sha256:" + "0" * 64)) + "\n",
                encoding="utf-8",
            )
            alias_dir = root / "commitment-alias"
            self._symlink_or_skip(alias_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security reviewer commitment contains a symlink component",
            ):
                self.review._load_reviewer_commitment(
                    alias_dir / "commitment.json",
                    expected_commit=self.review._FINAL_COMMIT,
                )

    def test_public_key_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-parent-key-") as temporary:
            root = Path(temporary)
            target_dir = root / "key-target"
            target_dir.mkdir()
            public_key = target_dir / "reviewer.public.pem"
            self._write_public_key(public_key, Ed25519PrivateKey.generate().public_key())
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment(self.review.public_key_id(public_key))) + "\n",
                encoding="utf-8",
            )
            alias_dir = root / "key-alias"
            self._symlink_or_skip(alias_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security reviewer public key contains a symlink component",
            ):
                self.review.validate_reviewer_authority(
                    commitment_path=commitment,
                    public_key=alias_dir / "reviewer.public.pem",
                    expected_commit=self.review._FINAL_COMMIT,
                    output=root / "authority-status.json",
                )

    def test_commitment_output_rejects_direct_symlink_without_mutating_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-output-symlink-") as temporary:
            root = Path(temporary)
            commitment = root / "commitment.json"
            commitment.write_text(
                json.dumps(self._commitment("sha256:" + "0" * 64)) + "\n",
                encoding="utf-8",
            )
            target = root / "target.json"
            target.write_text("sentinel\n", encoding="utf-8")
            output = root / "output.json"
            self._symlink_or_skip(output, target)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security reviewer commitment output contains a symlink component",
            ):
                self.review.normalize_reviewer_commitment(
                    input_path=commitment,
                    expected_commit=self.review._FINAL_COMMIT,
                    output=output,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_output_rejects_parent_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-review-output-parent-") as temporary:
            root = Path(temporary)
            target_dir = root / "output-target"
            target_dir.mkdir()
            alias_dir = root / "output-alias"
            self._symlink_or_skip(alias_dir, target_dir, target_is_directory=True)
            with self.assertRaisesRegex(
                self.review.FinalSecurityReviewPacketError,
                "security review submission validation output contains a symlink component",
            ):
                self.review._safe_output_file(
                    alias_dir / "status.json",
                    "security review submission validation output",
                )

    def test_reviewer_path_guard_checks_windows_reparse_attributes(self) -> None:
        raw = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("import stat", raw)
        self.assertIn("st_file_attributes", raw)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", raw)
        self.assertIn("_link_or_reparse_state", raw)
        self.assertIn("contains a reparse component", raw)

    def test_reviewer_commitment_contract_and_ten_path_preflight_are_fail_closed(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        packet = contract["security_review_packet"]
        review = contract["security_review"]
        authority = contract["authority_closure"]
        control = contract["control_source"]
        preparation = contract["preparation_state"]

        self.assertEqual(packet["reviewer_commitment"], "security-reviewer-commitment.json")
        self.assertEqual(packet["reviewer_intake_environment"], "production-ga-security-review-intake")
        self.assertEqual(packet["reviewer_commitment_variable"], "PSMATRIX_GA_SECURITY_REVIEWER_COMMITMENT_JSON")
        self.assertTrue(packet["reviewer_identity_precommit_required"])
        self.assertTrue(packet["reviewer_key_precommit_required"])
        self.assertFalse(packet["reviewer_private_key_allowed"])
        self.assertTrue(review["reviewer_commitment_required"])
        self.assertTrue(review["reviewer_identity_must_match_commitment"])
        self.assertTrue(review["reviewer_public_key_must_match_commitment"])
        self.assertTrue(authority["security_review_reviewer_identity_and_key_must_be_precommitted"])
        self.assertFalse(preparation["security_review_reviewer_commitment_provisioned"])

        allowlist = set(control["changed_path_allowlist"])
        self.assertEqual(len(allowlist), 10)
        self.assertIn("tests/test_ga_final_security_review_path_safety.py", allowlist)
        self.assertIn("tests/test_ga_final_security_review_parent_path_safety.py", allowlist)

        preflight = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("Verify exact ten-path closure", preflight)
        self.assertIn("$changed.Count -ne 10", preflight)
        self.assertIn("security_vulnerability_control_changed_paths=10", preflight)
        self.assertIn("tests/test_ga_final_security_review_path_safety.py", preflight)
        self.assertIn("tests/test_ga_final_security_review_parent_path_safety.py", preflight)
        self.assertIn("tests.test_ga_final_security_review_path_safety", preflight)
        self.assertIn("tests.test_ga_final_security_review_parent_path_safety", preflight)


if __name__ == "__main__":
    unittest.main()
