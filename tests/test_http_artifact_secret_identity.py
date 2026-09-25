import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPArtifactSecretIdentityTests(unittest.TestCase):
    def test_install_replaces_path_only_secret_loader(self):
        self.assertTrue(getattr(sessions, "_artifact_secret_identity_hardened", False))
        self.assertEqual(
            ProjectSessionStore._load_secret.__module__,
            "psmatrix.http_artifact_secret_hardening",
        )

    def test_concurrent_store_creation_converges_on_one_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"

            def create_store(_index: int) -> bytes:
                return ProjectSessionStore(home)._secret

            with ThreadPoolExecutor(max_workers=8) as pool:
                values = list(pool.map(create_store, range(16)))
            self.assertEqual(len(set(values)), 1)
            self.assertEqual(len(values[0]), 32)
            self.assertEqual((home / "http" / "artifact-hmac.key").read_bytes(), values[0])

    @unittest.skipUnless(os.name == "posix", "POSIX key permission semantics")
    def test_new_secret_is_mode_600(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            ProjectSessionStore(home)
            mode = (home / "http" / "artifact-hmac.key").stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_symlinked_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            key_parent = home / "http"
            key_parent.mkdir(parents=True)
            outside = Path(temp) / "outside.key"
            outside.write_bytes(b"K" * 32)
            os.chmod(outside, 0o600)
            (key_parent / "artifact-hmac.key").symlink_to(outside)
            with self.assertRaises(SessionError):
                ProjectSessionStore(home)

    @unittest.skipUnless(os.name == "posix", "POSIX hard-link semantics")
    def test_hardlinked_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            key_parent = home / "http"
            key_parent.mkdir(parents=True)
            outside = Path(temp) / "outside.key"
            outside.write_bytes(b"K" * 32)
            os.chmod(outside, 0o600)
            os.link(outside, key_parent / "artifact-hmac.key")
            with self.assertRaises(SessionError):
                ProjectSessionStore(home)

    @unittest.skipUnless(os.name == "posix", "POSIX key permission semantics")
    def test_broad_secret_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            key_parent = home / "http"
            key_parent.mkdir(parents=True)
            key = key_parent / "artifact-hmac.key"
            key.write_bytes(b"K" * 32)
            os.chmod(key, 0o644)
            with self.assertRaises(SessionError):
                ProjectSessionStore(home)


if __name__ == "__main__":
    unittest.main()
