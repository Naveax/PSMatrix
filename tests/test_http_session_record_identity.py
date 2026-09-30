import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPSessionRecordIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_http_session_record_identity_hardened", False))
        self.assertEqual(
            ProjectSessionStore.get.__module__,
            "psmatrix.http_session_record_hardening",
        )

    def test_get_no_longer_uses_path_based_read_or_atomic_touch(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            with mock.patch.object(sessions, "read_json", side_effect=AssertionError("path read")), mock.patch.object(
                sessions,
                "atomic_write_json",
                side_effect=AssertionError("path write"),
            ):
                loaded = store.get(record.session_id, "principal")
            self.assertEqual(loaded.session_id, record.session_id)

    @unittest.skipUnless(hasattr(os, "link"), "hardlinks unavailable")
    def test_hardlinked_session_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            path = store._record_path(record.session_id)
            alias = path.with_name("session-alias.json")
            try:
                os.link(path, alias)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal", touch=False)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_session_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            path = store._record_path(record.session_id)
            outside = path.with_name("outside.json")
            outside.write_bytes(path.read_bytes())
            path.unlink()
            try:
                path.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal", touch=False)

    @unittest.skipUnless(os.name == "posix", "POSIX directory replacement coverage")
    def test_session_directory_replacement_after_pin_fails_closed(self):
        from psmatrix import http_session_record_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            session_dir = store._record_path(record.session_id).parent
            moved = session_dir.with_name(session_dir.name + "-old")

            def replace(_store, pinned_dir):
                pinned_dir.rename(moved)
                pinned_dir.mkdir(mode=0o700)
                (pinned_dir / "session.json").write_bytes((moved / "session.json").read_bytes())

            with mock.patch.object(hardening, "_after_session_parent_pinned", side_effect=replace):
                with self.assertRaises(SessionError):
                    store.get(record.session_id, "principal", touch=False)


if __name__ == "__main__":
    unittest.main()
