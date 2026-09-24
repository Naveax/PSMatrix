import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPSessionTerminateIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_http_session_terminate_identity_hardened", False))
        self.assertEqual(
            ProjectSessionStore.terminate.__module__,
            "psmatrix.http_session_terminate_hardening",
        )

    def test_terminate_uses_session_record_lock(self):
        from psmatrix import http_session_record_hardening as record_hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            events = []

            @contextmanager
            def locked(_store, session_id):
                events.append(("enter", session_id))
                yield
                events.append(("exit", session_id))

            with mock.patch.object(record_hardening, "_session_record_lock", new=locked):
                store.terminate(record.session_id, "principal")

            self.assertEqual(
                events,
                [("enter", record.session_id), ("exit", record.session_id)],
            )

    def test_terminate_avoids_path_json_and_shutil_rmtree(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            store.upload(record, "nested/source.ps1", b"'ok'")
            with mock.patch.object(sessions, "read_json", side_effect=AssertionError("path read")), mock.patch.object(
                sessions,
                "atomic_write_json",
                side_effect=AssertionError("path write"),
            ), mock.patch.object(sessions.shutil, "rmtree", side_effect=AssertionError("path rmtree")):
                store.terminate(record.session_id, "principal")
            self.assertFalse(record.root.exists())
            self.assertFalse(record.home.exists())
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal", touch=False)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"), "POSIX symlink cleanup coverage")
    def test_symlink_inside_project_is_unlinked_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = ProjectSessionStore(root / "home")
            record = store.create("principal")
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            link = record.root / "outside-link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            store.terminate(record.session_id, "principal")
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(os.name in {"posix", "nt"}, "quarantine-race coverage requires POSIX or Windows")
    def test_quarantine_replacement_fails_closed_after_session_is_terminated(self):
        from psmatrix import http_session_terminate_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            store.upload(record, "source.ps1", b"'ok'")

            def replace(path):
                if ".project.terminated-" not in path.name:
                    return
                moved = path.with_name(path.name + "-old")
                path.rename(moved)
                path.mkdir(mode=0o700)

            with mock.patch.object(hardening, "_after_quarantine", side_effect=replace):
                with self.assertRaises(SessionError):
                    store.terminate(record.session_id, "principal")
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal", touch=False)
            self.assertFalse(record.root.exists())


if __name__ == "__main__":
    unittest.main()
