import os
import tempfile
import unittest
from pathlib import Path

from psmatrix import http_session_root_hardening as root_hardening
from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPSessionRootAuthorityTests(unittest.TestCase):
    def test_store_captures_initialized_root_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            self.assertIsNotNone(store._session_store_root_identity)
            root_hardening._assert_root(store)
            self.assertTrue(getattr(sessions, "_session_root_authority_hardened", False))

    def test_replacing_store_root_fails_closed_before_session_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            original = store.root.with_name("http-sessions-original")
            os.rename(store.root, original)
            store.root.mkdir()
            with self.assertRaises(SessionError):
                store.create("principal")
            self.assertEqual(list(store.root.iterdir()), [])

    def test_replacing_store_root_fails_closed_before_record_lookup(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            original = store.root.with_name("http-sessions-original")
            os.rename(store.root, original)
            store.root.mkdir()
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal")

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_symlink_replacement_of_store_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = ProjectSessionStore(root / "home")
            original = store.root.with_name("http-sessions-original")
            os.rename(store.root, original)
            outside = root / "outside"
            outside.mkdir()
            store.root.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(SessionError):
                store.create("principal")
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
