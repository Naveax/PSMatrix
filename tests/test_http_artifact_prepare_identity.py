import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError, SessionLimits


class HTTPArtifactPrepareIdentityTests(unittest.TestCase):
    def _record(self, root: Path):
        store = ProjectSessionStore(root / "home")
        record = store.create("principal")
        relative = ".psmatrix/mcp/report.json"
        store.upload(record, relative, b"artifact-source")
        return store, record, relative

    def test_install_replaces_path_reopen_prepare_implementation(self):
        self.assertTrue(getattr(sessions, "_artifact_prepare_boundary_hardened", False))
        self.assertEqual(
            ProjectSessionStore.prepare_artifact.__module__,
            "psmatrix.http_artifact_prepare_hardening",
        )

    def test_prepare_does_not_use_path_based_sha256_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record, relative = self._record(Path(temp))
            with mock.patch.object(sessions, "sha256_file", side_effect=AssertionError("path reopen")):
                prepared = store.prepare_artifact(record, relative, purpose="diagnostic")
            self.assertEqual(prepared["size"], len(b"artifact-source"))
            self.assertEqual(len(prepared["sha256"]), 64)

    def test_direct_reader_enforces_artifact_limit_while_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            limits = SessionLimits(max_artifact_bytes=1024)
            store = ProjectSessionStore(root / "home", limits)
            record = store.create("principal")
            target = record.root / ".psmatrix" / "mcp" / "report.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"x" * 1025)
            with self.assertRaises(SessionError):
                store.prepare_artifact(record, ".psmatrix/mcp/report.json", purpose="diagnostic")

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow semantics")
    def test_symlink_swap_between_resolution_and_direct_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store, record, relative = self._record(root)
            target = record.root / relative
            outside = root / "outside.bin"
            outside.write_bytes(b"artifact-source")
            original_resolve = sessions._resolve

            def resolve_then_swap(base: Path, value: str, *, must_exist: bool = False):
                result = original_resolve(base, value, must_exist=must_exist)
                if base == record.root and value == relative and must_exist:
                    target.unlink()
                    target.symlink_to(outside)
                return result

            with mock.patch.object(sessions, "_resolve", side_effect=resolve_then_swap):
                with self.assertRaises(SessionError):
                    store.prepare_artifact(record, relative, purpose="diagnostic")

    @unittest.skipUnless(os.name == "posix", "POSIX hard-link semantics")
    def test_hardlink_swap_between_resolution_and_direct_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store, record, relative = self._record(root)
            target = record.root / relative
            outside = root / "outside.bin"
            outside.write_bytes(b"artifact-source")
            original_resolve = sessions._resolve

            def resolve_then_swap(base: Path, value: str, *, must_exist: bool = False):
                result = original_resolve(base, value, must_exist=must_exist)
                if base == record.root and value == relative and must_exist:
                    target.unlink()
                    os.link(outside, target)
                return result

            with mock.patch.object(sessions, "_resolve", side_effect=resolve_then_swap):
                with self.assertRaises(SessionError):
                    store.prepare_artifact(record, relative, purpose="diagnostic")


if __name__ == "__main__":
    unittest.main()
