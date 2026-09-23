import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPUploadPublishIdentityTests(unittest.TestCase):
    def _store(self, root: Path):
        store = ProjectSessionStore(root / "home")
        return store, store.create("principal")

    def test_install_preserves_publish_boundary_beneath_quota_wrapper(self):
        from psmatrix import http_upload_quota_hardening as quota_hardening

        self.assertTrue(getattr(sessions, "_upload_publish_boundary_hardened", False))
        self.assertTrue(getattr(sessions, "_upload_quota_serialized", False))
        self.assertEqual(
            ProjectSessionStore.upload.__module__,
            "psmatrix.http_upload_quota_hardening",
        )
        self.assertIsNotNone(quota_hardening._ORIGINAL_UPLOAD)
        self.assertEqual(
            quota_hardening._ORIGINAL_UPLOAD.__module__,
            "psmatrix.http_upload_publish_hardening",
        )

    def test_nested_upload_publishes_exact_input_without_path_rehash(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record = self._store(Path(temp))
            payload = b"descriptor-bound-upload"
            with mock.patch.object(sessions, "sha256_file", side_effect=AssertionError("path rehash")):
                detail = store.upload(record, "nested/deeper/file.bin", payload)
            target = record.root / "nested" / "deeper" / "file.bin"
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(detail["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(detail["size"], len(payload))

    def test_existing_regular_target_is_atomically_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record = self._store(Path(temp))
            store.upload(record, "replace.txt", b"old")
            detail = store.upload(record, "replace.txt", b"new-value")
            self.assertEqual((record.root / "replace.txt").read_bytes(), b"new-value")
            self.assertEqual(detail["sha256"], hashlib.sha256(b"new-value").hexdigest())

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative parent semantics")
    def test_symlinked_upload_parent_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store, record = self._store(root)
            outside = root / "outside"
            outside.mkdir()
            (record.root / "nested").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(SessionError):
                store.upload(record, "nested/file.bin", b"blocked")
            self.assertFalse((outside / "file.bin").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX hard-link semantics")
    def test_existing_hardlinked_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store, record = self._store(root)
            outside = root / "outside.bin"
            outside.write_bytes(b"shared")
            target = record.root / "shared.bin"
            os.link(outside, target)
            with self.assertRaises(SessionError):
                store.upload(record, "shared.bin", b"replacement")
            self.assertEqual(outside.read_bytes(), b"shared")


if __name__ == "__main__":
    unittest.main()
