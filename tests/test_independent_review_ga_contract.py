import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair
from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT / "scripts" / "ga" / "independent_review_dossier.py"
SUBMISSION = ROOT / "scripts" / "ga" / "independent_review_submission.py"
CONTRACT = ROOT / "ga-packs" / "06-independent-review" / "authority-contract.json"
README = ROOT / "ga-packs" / "06-independent-review" / "README.md"
COMMIT = "a" * 40


class IndependentReviewGAContractTests(unittest.TestCase):
    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = dict(os.environ)
        merged["PYTHONPATH"] = str(ROOT / "src")
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            env=merged,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _release(self, root: Path, version: str = "2.0.0") -> tuple[Path, Path, Path, Path]:
        artifacts = root / "release"
        artifacts.mkdir()
        source = artifacts / f"psmatrix-{version}-source.zip"
        source.write_bytes(b"canonical-source")
        wheel = artifacts / f"psmatrix-{version}-py3-none-any.whl"
        wheel.write_bytes(b"canonical-wheel")
        private = root / "release.private.pem"
        public = root / "release.public.pem"
        generate_ed25519_keypair(private, public)
        manifest = artifacts / f"psmatrix-{version}-release.json"
        create_release_manifest(
            [source, wheel],
            manifest,
            version=version,
            signing_private_key=private,
            signing_public_key=public,
        )
        return artifacts, manifest, private, public

    def _build_dossier(self, root: Path, version: str = "2.0.0") -> tuple[Path, Path, Path]:
        artifacts, manifest, _, public = self._release(root, version)
        output = root / "dossier"
        result = self._run(
            str(DOSSIER),
            "build",
            "--release-manifest", str(manifest),
            "--artifact-dir", str(artifacts),
            "--release-public-key", str(public),
            "--release-commit", COMMIT,
            "--output-dir", str(output),
            env={"SOURCE_DATE_EPOCH": "0"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return output, manifest, public

    def _completed_report(self, dossier: Path) -> dict:
        report = json.loads((dossier / "review-report.template.json").read_text(encoding="utf-8"))
        report["status"] = "PASS"
        report["completed_at"] = datetime.now(UTC).isoformat()
        report["reviewer"] = {
            "name": "Independent Reviewer",
            "organization": "External Security Laboratory",
            "role": "Principal Security Reviewer",
            "contact": "reviewer@example.test",
            "conflict_of_interest": False,
            "key_controlled_by_reviewer": True,
        }
        report["review_hours"] = 24
        for section in report["sections"]:
            section["status"] = "PASS"
            section["summary"] = f"Reviewed {section['id']} controls."
            section["evidence"] = ["dossier-source", "release-binding"]
        report["findings"] = [
            {
                "id": "IR-001",
                "severity": "low",
                "title": "Documentation clarification",
                "description": "A non-blocking documentation clarification was identified.",
                "recommendation": "Clarify the operator wording.",
            }
        ]
        report["finding_counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}
        report["conclusion"] = "The reviewed release has no critical or high findings and satisfies the stated review scope."
        return report

    def test_scripts_are_valid_python(self) -> None:
        for path in (DOSSIER, SUBMISSION):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_dossier_is_deterministic_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts, manifest, _, public = self._release(root)
            outputs = []
            for name in ("first", "second"):
                output = root / name
                result = self._run(
                    str(DOSSIER), "build",
                    "--release-manifest", str(manifest),
                    "--artifact-dir", str(artifacts),
                    "--release-public-key", str(public),
                    "--release-commit", COMMIT,
                    "--output-dir", str(output),
                    env={"SOURCE_DATE_EPOCH": "0"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(output)
            first_zip = outputs[0] / "psmatrix-independent-review-dossier.zip"
            second_zip = outputs[1] / "psmatrix-independent-review-dossier.zip"
            self.assertEqual(first_zip.read_bytes(), second_zip.read_bytes())
            verify = self._run(str(DOSSIER), "verify", "--dossier", str(outputs[0]))
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(json.loads(verify.stdout)["status"], "PASS")

    def test_tampered_dossier_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            dossier, _, _ = self._build_dossier(Path(temp))
            source = next(dossier.glob("*-source.zip"))
            source.write_bytes(source.read_bytes() + b"tamper")
            verify = self._run(str(DOSSIER), "verify", "--dossier", str(dossier))
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("digest mismatch", verify.stderr)

    def test_completed_report_signs_and_verifies_with_reviewer_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dossier, _, _ = self._build_dossier(root)
            report_path = root / "independent-security-review-report.json"
            report_path.write_text(json.dumps(self._completed_report(dossier), indent=2) + "\n", encoding="utf-8")
            proof = root / "security-review-proof-input.json"
            prepared = self._run(
                str(SUBMISSION), "prepare",
                "--report", str(report_path),
                "--dossier", str(dossier),
                "--output", str(proof),
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            reviewer_private = root / "reviewer.private.pem"
            reviewer_public = root / "reviewer.public.pem"
            generate_ed25519_keypair(reviewer_private, reviewer_public)
            attestation = root / "security-review.dsse.json"
            signed = self._run(
                str(SUBMISSION), "sign",
                "--proof", str(proof),
                "--private-key", str(reviewer_private),
                "--public-key", str(reviewer_public),
                "--output", str(attestation),
            )
            self.assertEqual(signed.returncode, 0, signed.stderr)
            reviewer_private.unlink()
            verification = root / "security-review-verification.json"
            verified = self._run(
                str(SUBMISSION), "verify",
                "--attestation", str(attestation),
                "--public-key", str(reviewer_public),
                "--report", str(report_path),
                "--dossier", str(dossier),
                "--output", str(verification),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            value = json.loads(verified.stdout)
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["release_commit"], COMMIT)
            self.assertEqual(value["review_report_sha256"], sha256_file(report_path))
            self.assertFalse(value["ga_eligible"])

    def test_conflict_or_blocking_finding_is_rejected(self) -> None:
        cases = ("conflict", "high")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                dossier, _, _ = self._build_dossier(root)
                report = self._completed_report(dossier)
                if case == "conflict":
                    report["reviewer"]["conflict_of_interest"] = True
                else:
                    report["findings"].append({
                        "id": "IR-002",
                        "severity": "high",
                        "title": "Blocking issue",
                        "description": "A high-severity issue remains open.",
                    })
                    report["finding_counts"]["high"] = 1
                report_path = root / "report.json"
                report_path.write_text(json.dumps(report), encoding="utf-8")
                prepared = self._run(
                    str(SUBMISSION), "prepare",
                    "--report", str(report_path),
                    "--dossier", str(dossier),
                    "--output", str(root / "proof.json"),
                )
                self.assertNotEqual(prepared.returncode, 0)

    def test_authority_contract_is_external_and_fail_closed(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertTrue(contract["authority"]["reviewer_must_be_external"])
        self.assertTrue(contract["authority"]["reviewer_controls_signing_key"])
        self.assertFalse(contract["authority"]["private_key_in_dossier"])
        self.assertEqual(contract["findings"]["critical_allowed"], 0)
        self.assertEqual(contract["findings"]["high_allowed"], 0)
        self.assertTrue(contract["submission"]["final_evaluator_cross_binding_required"])
        self.assertFalse(contract["completion"]["source_preflight_can_complete_pack"])
        text = README.read_text(encoding="utf-8")
        self.assertIn("reviewer-controlled", text)
        self.assertIn("READY_FOR_REVIEWER", text)


if __name__ == "__main__":
    unittest.main()
