import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.signing import (
    SigningError,
    TrustStore,
    generate_ed25519_keypair,
    public_key_id,
    sign_bytes,
)


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class SigningPathSecurityTests(unittest.TestCase):
    def test_sign_bytes_rejects_reparse_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {private_key})):
                with self.assertRaisesRegex(SigningError, "symlink or reparse point"):
                    sign_bytes(b"payload", private_key)

    def test_public_key_id_rejects_reparse_public_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {public_key})):
                with self.assertRaisesRegex(SigningError, "symlink or reparse point"):
                    public_key_id(public_key)

    def test_trust_store_get_rejects_reparse_stored_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            store = TrustStore(root / "home")
            trusted = store.add("worker-a", "worker", public_key)

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {trusted.public_key})):
                with self.assertRaisesRegex(SigningError, "symlink or reparse point"):
                    store.get("worker-a", "worker")

    def test_trust_store_rejects_reparse_index_after_initialization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            store = TrustStore(root / "home")
            store.add("worker-a", "worker", public_key)

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {store.index})):
                with self.assertRaisesRegex(SigningError, "symlink or reparse point"):
                    store.list()

    @unittest.skipIf(os.name == "nt", "ordinary Windows test accounts may not be allowed to create symlinks")
    def test_public_key_id_rejects_intermediate_posix_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            private_key = real / "private.pem"
            public_key = real / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)

            with self.assertRaisesRegex(SigningError, "symlink or reparse point"):
                public_key_id(alias / "public.pem")


if __name__ == "__main__":
    unittest.main()
