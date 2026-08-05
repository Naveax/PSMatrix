import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.attestation import build_slsa_provenance, sign_provenance, verify_provenance
from psmatrix.signing import (
    SigningError,
    TrustStore,
    create_dsse_envelope,
    generate_ed25519_keypair,
    verify_dsse_envelope,
)


class SigningTests(unittest.TestCase):
    def test_ed25519_dsse_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generated = generate_ed25519_keypair(private_key, public_key)
            self.assertEqual(generated["algorithm"], "Ed25519")
            envelope = create_dsse_envelope({"answer": 42}, private_key, public_key)
            verified = verify_dsse_envelope(envelope, public_key)
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["statement"]["answer"], 42)
            envelope["payload"] = envelope["payload"][:-2] + "AA"
            with self.assertRaises(SigningError):
                verify_dsse_envelope(envelope, public_key)

    def test_trust_store_detects_key_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first_private = root / "first-private.pem"
            first_public = root / "first-public.pem"
            second_private = root / "second-private.pem"
            second_public = root / "second-public.pem"
            generate_ed25519_keypair(first_private, first_public)
            generate_ed25519_keypair(second_private, second_public)
            store = TrustStore(root / "home")
            trusted = store.add("worker-a", "worker", first_public)
            self.assertEqual(store.get("worker-a", "worker").key_id, trusted.key_id)
            trusted.public_key.write_bytes(second_public.read_bytes())
            with self.assertRaises(SigningError):
                store.get("worker-a", "worker")


    def test_trust_rotation_and_revocation_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first_private, first_public = root / "first.pem", root / "first.pub"
            second_private, second_public = root / "second.pem", root / "second.pub"
            generate_ed25519_keypair(first_private, first_public)
            generate_ed25519_keypair(second_private, second_public)
            store = TrustStore(root / "home")
            first = store.add("worker-a", "worker", first_public)
            second = store.rotate("worker-a", "worker", second_public, expected_current_key_id=first.key_id)
            self.assertNotEqual(first.key_id, second.key_id)
            self.assertEqual(store.get("worker-a", "worker").key_id, second.key_id)
            revoked = store.revoke("worker-a", "worker", reason="retired")
            self.assertEqual(revoked["status"], "revoked")
            with self.assertRaises(Exception):
                store.get("worker-a", "worker")

    def test_slsa_provenance_subject_is_bound_to_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "evidence.zip"
            artifact.write_bytes(b"evidence")
            source = root / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            report = {
                "schema": 6,
                "tool_version": "0.9.0",
                "started_at": "2026-08-03T00:00:00+00:00",
                "finished_at": "2026-08-03T00:00:01+00:00",
                "status": "PASS",
                "matrix": {"versions": ["7.6.4"]},
                "targets": [{"source": str(source), "source_sha256": "a" * 64, "runtime_id": "powershell-7.6.4-linux-x64"}],
            }
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            statement = build_slsa_provenance(artifact=artifact, report=report, builder_id="urn:psmatrix:test")
            envelope = sign_provenance(statement, private_key, public_key)
            verified = verify_provenance(envelope, public_key, artifact=artifact)
            self.assertTrue(verified["artifact_valid"])
            self.assertEqual(verified["statement"]["predicateType"], "https://slsa.dev/provenance/v1")
            artifact.write_bytes(b"changed")
            with self.assertRaises(Exception):
                verify_provenance(envelope, public_key, artifact=artifact)


if __name__ == "__main__":
    unittest.main()

class OpenSSLHardeningTests(unittest.TestCase):
    def test_openssl_environment_is_sanitized(self):
        from unittest.mock import patch
        import os
        import subprocess
        import psmatrix.signing as signing

        completed = subprocess.CompletedProcess(["openssl"], 0, stdout=b"ok", stderr=b"")
        poisoned = {
            "OPENSSL_CONF": "/tmp/evil.cnf",
            "OPENSSL_MODULES": "/tmp/modules",
            "OPENSSL_ENGINES": "/tmp/engines",
            "RANDFILE": "/tmp/rand",
        }
        with patch.dict(os.environ, poisoned, clear=False), \
             patch.object(signing, "_openssl", return_value="openssl"), \
             patch.object(signing.subprocess, "run", return_value=completed) as run:
            self.assertEqual(signing._run_openssl(["version"]), b"ok")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 20)
        for name in poisoned:
            self.assertNotIn(name, kwargs["env"])
