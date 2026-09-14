import tempfile
import threading
import unittest
from pathlib import Path

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError, SessionLimits


class HTTPUploadQuotaSerializationTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_upload_quota_serialized", False))
        self.assertEqual(
            ProjectSessionStore.upload.__module__,
            "psmatrix.http_upload_quota_hardening",
        )

    def test_two_store_instances_share_one_session_quota_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            limits = SessionLimits(
                max_files=8,
                max_project_bytes=2048,
                max_upload_bytes=1536,
                max_artifact_bytes=2048,
                max_text_bytes=1024,
            )
            first = ProjectSessionStore(home, limits)
            created = first.create("principal")
            second = ProjectSessionStore(home, limits)
            loaded = second.get(created.session_id, "principal", touch=False)

            barrier = threading.Barrier(3)
            successes = []
            failures = []

            def upload(store, record, name):
                barrier.wait()
                try:
                    store.upload(record, name, b"X" * 1200)
                    successes.append(name)
                except SessionError as exc:
                    failures.append((name, str(exc)))

            threads = [
                threading.Thread(target=upload, args=(first, created, "a.bin")),
                threading.Thread(target=upload, args=(second, loaded, "b.bin")),
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join()

            self.assertEqual(len(successes), 1, (successes, failures))
            self.assertEqual(len(failures), 1, (successes, failures))
            files, total = sessions._directory_usage(created.root)
            self.assertEqual(files, 1)
            self.assertEqual(total, 1200)
            self.assertIn("quota", failures[0][1].lower())

    def test_different_sessions_do_not_share_the_same_lock(self):
        from psmatrix import http_upload_quota_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            first = store.create("principal")
            second = store.create("principal")
            self.assertIsNot(hardening._session_lock(first), hardening._session_lock(second))


if __name__ == "__main__":
    unittest.main()
