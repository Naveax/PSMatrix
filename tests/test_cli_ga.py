import json
import os
import subprocess
import sys
import tempfile
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
