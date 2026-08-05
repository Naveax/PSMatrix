import json
import subprocess
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from psmatrix.ga import verify_ga_proof
from psmatrix.security_review import (
    SecurityReviewError,
    build_security_review_packet,
    finalize_security_review,
)
from psmatrix.signing import generate_ed25519_keypair
from psmatrix.util import sha256_file


class IndependentSecurityReviewTests(unittest.TestCase):
    def _fixture(self, root: Path):
        repo = root / "repo"
        repo.mkdir()
        (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
        (repo / "PRODUCTION_GA.md").write_text("# GA\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.test"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        source = root / "source.zip"
        source.write_bytes(b"source-archive")
        release = root / "release.json"
        release.write_text(json.dumps({"schema": 1, "kind": "psmatrix.release-manifest"}), encoding="utf-8")
        return repo, source, release, commit

    def _report(self, *, source: Path, release: Path, commit: str):
        sections = {}
        for name in (
            "architecture", "authentication", "authorization", "sandbox", "supply-chain",
            "recovery", "operations", "privacy", "release-process",
        ):
            sections[name] = {"status": "REVIEWED", "summary": f"Reviewed {name}", "evidence": [], "findings": []}
        return {
            "schema": 1,
            "kind": "psmatrix.independent-security-review",
            "status": "PASS",
            "observed_at": datetime.now(UTC).isoformat(),
            "reviewed_commit": commit,
            "reviewed_release_sha256": sha256_file(release),
            "reviewed_source_sha256": sha256_file(source),
            "review_hours": 16,
            "reviewer": {
                "name": "External Reviewer",
                "organization": "Independent Security Lab",
                "role": "Principal Reviewer",
                "contact": "reviewer@example.test",
                "conflict_of_interest": False,
                "key_controlled_by_reviewer": True,
            },
            "methodologies": [
                "architecture-review", "threat-model-review", "manual-code-review", "test-evidence-review",
            ],
            "sections": sections,
            "findings": [
                {"id": "REV-001", "severity": "low", "title": "Documentation note", "disposition": "accepted"}
            ],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0},
            "limitations": [],
            "reviewer_declaration": "I performed this review independently and control the signing key.",
        }

    def test_review_packet_is_deterministic_and_contains_no_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, source, release, commit = self._fixture(root)
            first = root / "first.zip"
            second = root / "second.zip"
            a = build_security_review_packet(root=repo, source_archive=source, release_manifest=release, output=first)
            b = build_security_review_packet(root=repo, source_archive=source, release_manifest=release, output=second)
            self.assertEqual(a["reviewed_commit"], commit)
            self.assertEqual(a["sha256"], b["sha256"])
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertIn("psmatrix-independent-security-review/review-report.template.json", names)
                joined = b"".join(archive.read(name) for name in names)
                self.assertNotIn(b"BEGIN PRIVATE KEY", joined)

    def test_completed_review_is_signed_and_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _repo, source, release, commit = self._fixture(root)
            report = root / "review.json"
            report.write_text(json.dumps(self._report(source=source, release=release, commit=commit)), encoding="utf-8")
            private = root / "reviewer-private.pem"
            public = root / "reviewer-public.pem"
            generate_ed25519_keypair(private, public)
            result_path = root / "review-result.json"
            attestation = root / "review.dsse.json"
            result = finalize_security_review(
                report_path=report,
                source_archive=source,
                release_manifest=release,
                private_key=private,
                public_key=public,
                result_output=result_path,
                attestation_output=attestation,
            )
            self.assertEqual(result.report_sha256, sha256_file(report))
            envelope = json.loads(attestation.read_text(encoding="utf-8"))
            verified = verify_ga_proof(envelope, public_key=public, expected_type="security-review")
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["result"]["assertions"]["reviewed_commit"], commit)

    def test_conflicted_reviewer_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _repo, source, release, commit = self._fixture(root)
            value = self._report(source=source, release=release, commit=commit)
            value["reviewer"]["conflict_of_interest"] = True
            report = root / "review.json"
            report.write_text(json.dumps(value), encoding="utf-8")
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            with self.assertRaises(SecurityReviewError):
                finalize_security_review(
                    report_path=report, source_archive=source, release_manifest=release,
                    private_key=private, public_key=public,
                    result_output=root / "result.json", attestation_output=root / "proof.json",
                )

    def test_incomplete_section_and_summary_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _repo, source, release, commit = self._fixture(root)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            for case in ("section", "summary"):
                value = self._report(source=source, release=release, commit=commit)
                if case == "section":
                    value["sections"]["privacy"]["status"] = "NOT_REVIEWED"
                else:
                    value["summary"]["low"] = 0
                report = root / f"{case}.json"
                report.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(SecurityReviewError):
                    finalize_security_review(
                        report_path=report, source_archive=source, release_manifest=release,
                        private_key=private, public_key=public,
                        result_output=root / f"{case}-result.json", attestation_output=root / f"{case}-proof.json",
                    )


if __name__ == "__main__":
    unittest.main()
