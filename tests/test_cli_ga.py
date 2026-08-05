import json
import os
import subprocess
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
import unittest
from pathlib import Path

from psmatrix.signing import generate_ed25519_keypair


class CLIGATests(unittest.TestCase):
    def _run(self, root: Path, *args: str):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        return subprocess.run(
            [sys.executable, "-m", "psmatrix", "--home", str(root / "home"), *args],
            cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_init_and_incomplete_evaluation_use_distinct_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            created = self._run(root, "ga", "init", "--output", "ga-policy.json")
            self.assertEqual(created.returncode, 0, created.stderr)
            evaluated = self._run(root, "ga", "evaluate", "--policy", "ga-policy.json", "--output", "ga-evaluation.json")
            self.assertEqual(evaluated.returncode, 2, evaluated.stderr)
            value = json.loads((root / "ga-evaluation.json").read_text())
            self.assertEqual(value["status"], "INCOMPLETE")

    def test_rotation_drill_and_proof_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            created = self._run(root, "ga", "key-rotation-drill", "--private-key", str(private), "--public-key", str(public), "--output", "rotation.json")
            self.assertEqual(created.returncode, 0, created.stderr)
            verified = self._run(root, "ga", "proof-verify", "--type", "key-rotation", "--attestation", "rotation.json", "--public-key", str(public))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

    def test_independent_review_packet_finalize_and_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Reviewer Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "reviewer@example.test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)
            source = root / "source.zip"
            source.write_bytes(b"source")
            release = root / "release.json"
            release.write_text('{"schema":1}', encoding="utf-8")
            packet = self._run(
                root, "ga", "review-packet", "--root", str(repo),
                "--source-archive", str(source), "--release-manifest", str(release),
                "--output", "review-packet.zip",
            )
            self.assertEqual(packet.returncode, 0, packet.stderr)
            with zipfile.ZipFile(root / "review-packet.zip") as archive:
                template = json.loads(archive.read("psmatrix-independent-security-review/review-report.template.json"))
            template["status"] = "PASS"
            template["observed_at"] = datetime.now(UTC).isoformat()
            template["review_hours"] = 12
            template["reviewer"] = {
                "name": "External Reviewer", "organization": "Security Lab",
                "role": "Principal Reviewer", "contact": "reviewer@example.test",
                "conflict_of_interest": False, "key_controlled_by_reviewer": True,
            }
            for section in template["sections"].values():
                section["status"] = "REVIEWED"
                section["summary"] = "Reviewed"
            template["findings"] = []
            template["summary"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            template["reviewer_declaration"] = "Independent review completed."
            report = root / "review.json"
            report.write_text(json.dumps(template), encoding="utf-8")
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            finalized = self._run(
                root, "ga", "review-finalize", "--report", str(report),
                "--source-archive", str(source), "--release-manifest", str(release),
                "--private-key", str(private), "--public-key", str(public),
                "--result-output", "review-result.json", "--attestation-output", "review.dsse.json",
            )
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            verified = self._run(
                root, "ga", "proof-verify", "--type", "security-review",
                "--attestation", "review.dsse.json", "--public-key", str(public),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

    def test_sign_re_evaluates_policy_and_refuses_incomplete_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            self.assertEqual(self._run(root, "ga", "init", "--output", "ga-policy.json").returncode, 0)
            signed = self._run(
                root, "ga", "sign", "--policy", "ga-policy.json",
                "--private-key", str(private), "--public-key", str(public),
                "--output", "production-ga.dsse.json",
            )
            self.assertNotEqual(signed.returncode, 0)
            self.assertFalse((root / "production-ga.dsse.json").exists())



if __name__ == "__main__":
    unittest.main()
