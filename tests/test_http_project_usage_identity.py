import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPProjectUsageIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_project_usage_identity_hardened", False))
        self.assertEqual(
            sessions._directory_usage.__module__,
            "psmatrix.http_project_usage_hardening",
        )

    def test_nested_usage_is_counted_without_pathlib_rglob(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            store.upload(record, "a.txt", b"abc")
            store.upload(record, "nested/b.txt", b"12345")
            with mock.patch.object(Path, "rglob", side_effect=AssertionError("path traversal")):
                files, total = sessions._directory_usage(record.root)
            self.assertEqual(files, 2)
            self.assertEqual(total, 8)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_in_project_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = ProjectSessionStore(root / "home")
            record = store.create("principal")
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = record.root / "link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(SessionError):
                sessions._directory_usage(record.root)

    @unittest.skipUnless(hasattr(os, "link"), "hardlinks unavailable")
    def test_hardlink_in_project_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = ProjectSessionStore(root / "home")
            record = store.create("principal")
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = record.root / "hard.txt"
            try:
                os.link(outside, link)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(SessionError):
                sessions._directory_usage(record.root)

    @unittest.skipUnless(os.name == "posix", "POSIX replacement-race coverage")
    def test_file_replacement_after_open_fails_closed(self):
        from psmatrix import http_project_usage_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            store.upload(record, "source.txt", b"original")
            target = record.root / "source.txt"
            moved = record.root / "source-old.txt"

            def replace(path):
                if path != target or moved.exists():
                    return
                path.rename(moved)
                path.write_bytes(b"replacement")

            with mock.patch.object(hardening, "_after_usage_entry_open", side_effect=replace):
                with self.assertRaises(SessionError):
                    sessions._directory_usage(record.root)


if __name__ == "__main__":
    unittest.main()
