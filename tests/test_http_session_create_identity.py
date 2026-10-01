import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPSessionCreateIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_http_session_create_identity_hardened", False))
        self.assertEqual(
            ProjectSessionStore.create.__module__,
            "psmatrix.http_session_create_hardening",
        )

    def test_create_no_longer_uses_path_atomic_session_record_write(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            with mock.patch.object(
                sessions,
                "atomic_write_json",
                side_effect=AssertionError("path atomic write"),
            ):
                record = store.create("principal")
            self.assertEqual(store.get(record.session_id, "principal", touch=False).session_id, record.session_id)
            self.assertTrue((record.root.parent / "audit.jsonl").is_file())

    @unittest.skipUnless(os.name == "posix", "POSIX create-race coverage")
    def test_created_session_directory_replacement_fails_closed(self):
        from psmatrix import http_session_create_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            moved = []

            def replace(_store, session_dir):
                detached = session_dir.with_name(session_dir.name + "-detached")
                session_dir.rename(detached)
                session_dir.mkdir(mode=0o700)
                moved.append(detached)

            with mock.patch.object(hardening, "_after_session_directory_created", side_effect=replace):
                with self.assertRaises(SessionError):
                    store.create("principal")
            self.assertEqual(len(moved), 1)
            self.assertTrue(moved[0].is_dir())

    def test_created_session_tree_has_direct_expected_children(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            session_dir = record.root.parent
            self.assertTrue(record.root.is_dir())
            self.assertTrue(record.home.is_dir())
            self.assertTrue((session_dir / "session.json").is_file())
            self.assertFalse(record.root.is_symlink())
            self.assertFalse(record.home.is_symlink())
            self.assertFalse((session_dir / "session.json").is_symlink())


if __name__ == "__main__":
    unittest.main()
