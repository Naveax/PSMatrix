import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError, SessionLimits


class HTTPUploadQuotaSerializationTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_project_usage_identity_hardened", False))
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
            successes: list[str] = []
            failures: list[tuple[str, str]] = []

            def upload(store: ProjectSessionStore, record, name: str) -> None:
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

    def test_lock_authority_is_shared_by_root_identity_and_session_id(self):
        from psmatrix import http_upload_quota_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            first_store = ProjectSessionStore(home)
            first = first_store.create("principal")
            second_store = ProjectSessionStore(home)
            loaded = second_store.get(first.session_id, "principal", touch=False)
            other = first_store.create("principal")

            first_key = hardening._session_key(first_store, first)
            second_key = hardening._session_key(second_store, loaded)
            other_key = hardening._session_key(first_store, other)
            self.assertEqual(first_key, second_key)
            self.assertNotEqual(first_key, other_key)

            with hardening._session_lock(first_store, first):
                shared = hardening._SESSION_LOCKS[first_key]
                self.assertEqual(hardening._SESSION_LOCK_USERS[first_key], 1)
                with hardening._session_lock(second_store, loaded):
                    self.assertIs(hardening._SESSION_LOCKS[first_key], shared)
                    self.assertEqual(hardening._SESSION_LOCK_USERS[first_key], 2)
                self.assertIs(hardening._SESSION_LOCKS[first_key], shared)
                self.assertEqual(hardening._SESSION_LOCK_USERS[first_key], 1)

            self.assertNotIn(first_key, hardening._SESSION_LOCKS)
            self.assertNotIn(first_key, hardening._SESSION_LOCK_USERS)

    def test_cross_process_upload_waits_for_session_quota_lock(self):
        from psmatrix import http_upload_quota_hardening as hardening
        from psmatrix.util import exclusive_lock

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            ready = root / "ready"
            store = ProjectSessionStore(home)
            record = store.create("principal")
            lock_path = hardening._cross_process_lock_path(store, record)

            child = r"""
import sys
from pathlib import Path
from psmatrix.http_sessions import ProjectSessionStore

home = Path(sys.argv[1])
session_id = sys.argv[2]
ready = Path(sys.argv[3])
store = ProjectSessionStore(home)
record = store.get(session_id, "principal", touch=False)
ready.write_text("ready", encoding="utf-8")
store.upload(record, "child.bin", b"X" * 32)
print("done", flush=True)
"""
            process = None
            try:
                with exclusive_lock(lock_path):
                    process = subprocess.Popen(
                        [sys.executable, "-c", child, str(home), record.session_id, str(ready)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=dict(os.environ),
                    )
                    deadline = time.monotonic() + 10.0
                    while not ready.exists() and process.poll() is None:
                        if time.monotonic() >= deadline:
                            self.fail("child did not reach upload boundary")
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    time.sleep(0.25)
                    self.assertIsNone(process.poll(), "child upload bypassed the cross-process quota lock")

                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "done")
                self.assertEqual((record.root / "child.bin").read_bytes(), b"X" * 32)
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
