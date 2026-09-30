import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import HashChainAudit, SessionError


class HTTPAuditLogIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_http_audit_log_identity_hardened", False))
        self.assertEqual(HashChainAudit.append.__module__, "psmatrix.http_audit_log_hardening")
        self.assertEqual(HashChainAudit.verify.__module__, "psmatrix.http_audit_log_hardening")

    def test_distinct_instances_serialize_concurrent_appends(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            failures = []

            def append(index):
                try:
                    HashChainAudit(path).append(
                        principal="principal",
                        action="test.concurrent",
                        detail={"index": index},
                    )
                except Exception as exc:
                    failures.append(exc)

            threads = [threading.Thread(target=append, args=(index,)) for index in range(24)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(failures, [])
            status = HashChainAudit(path).verify()
            self.assertTrue(status["valid"], status)
            self.assertEqual(status["records"], 24)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_audit_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.jsonl"
            outside.write_text("", encoding="utf-8")
            path = root / "audit.jsonl"
            try:
                path.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(SessionError):
                HashChainAudit(path).append(principal="principal", action="test", detail={})
            self.assertFalse(HashChainAudit(path).verify()["valid"])

    @unittest.skipUnless(hasattr(os, "link"), "hardlinks unavailable")
    def test_hardlinked_audit_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "audit.jsonl"
            audit = HashChainAudit(path)
            audit.append(principal="principal", action="test", detail={})
            alias = root / "alias.jsonl"
            try:
                os.link(path, alias)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(SessionError):
                audit.append(principal="principal", action="test", detail={})
            self.assertFalse(audit.verify()["valid"])

    @unittest.skipUnless(os.name == "posix", "POSIX rename-race coverage")
    def test_path_replacement_after_lock_fails_closed(self):
        from psmatrix import http_audit_log_hardening as hardening

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "audit.jsonl"
            audit = HashChainAudit(path)
            audit.append(principal="principal", action="seed", detail={})
            original = path.read_bytes()
            moved = root / "old-audit.jsonl"

            def replace(locked_path, _fd):
                locked_path.rename(moved)
                locked_path.write_bytes(original)

            with mock.patch.object(hardening, "_after_lock_acquired", side_effect=replace):
                with self.assertRaises(SessionError):
                    audit.append(principal="principal", action="race", detail={})


if __name__ == "__main__":
    unittest.main()
