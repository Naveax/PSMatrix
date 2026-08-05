import os
import shutil
import tempfile
import unittest
from pathlib import Path

from psmatrix.pki import apply_rotation_bundle, create_ca, create_rotation_bundle, issue_certificate, verify_key_pair
from psmatrix.signing import generate_ed25519_keypair


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL unavailable")
class PKITests(unittest.TestCase):
    def test_ca_issue_and_signed_rotation_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ca = create_ca(root / "ca", common_name="PSMatrix Test CA", days=30)
            leaf = issue_certificate(
                Path(ca["certificate"]), Path(ca["private_key"]), root / "leaf",
                common_name="worker-a", role="server", dns_names=["localhost"], days=7,
            )
            verify_key_pair(Path(leaf["certificate"]), Path(leaf["private_key"]))
            signing_private, signing_public = root / "release.pem", root / "release.pub"
            generate_ed25519_keypair(signing_private, signing_public)
            bundle = root / "rotation.zip"
            create_rotation_bundle(
                bundle, identity="worker-a", role="worker-server",
                certificate=Path(leaf["certificate"]), private_key=Path(leaf["private_key"]),
                ca_certificate=Path(ca["certificate"]), signing_private_key=signing_private,
                signing_public_key=signing_public, generation=2,
            )
            result = apply_rotation_bundle(
                bundle, root / "active", signing_public_key=signing_public,
                expected_identity="worker-a", expected_role="worker-server",
            )
            self.assertEqual(result["generation"], 2)
            if os.name != "nt":
                self.assertEqual((root / "active" / "private-key.pem").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

class PKIHardeningTests(unittest.TestCase):
    def test_rejects_subject_injection_characters(self):
        from psmatrix.pki import PKIError
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(PKIError):
                create_ca(root / "bad-ca", common_name="safe/CN=evil", days=30)
            with self.assertRaises(PKIError):
                create_ca(root / "bad-ca-2", common_name="safe\nsubjectAltName=DNS:evil", days=30)

    def test_openssl_runner_has_timeout_and_sanitized_environment(self):
        from unittest.mock import patch
        import subprocess
        import psmatrix.pki as pki

        completed = subprocess.CompletedProcess(["openssl"], 0, stdout=b"ok", stderr=b"")
        with patch.dict(os.environ, {"OPENSSL_CONF": "/tmp/evil.cnf", "OPENSSL_MODULES": "/tmp/modules"}, clear=False), \
             patch.object(pki, "_openssl", return_value="openssl"), \
             patch.object(pki.subprocess, "run", return_value=completed) as run:
            self.assertEqual(pki._run(["version"]), b"ok")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 30)
        self.assertNotIn("OPENSSL_CONF", kwargs["env"])
        self.assertNotIn("OPENSSL_MODULES", kwargs["env"])
