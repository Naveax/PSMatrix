import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import psmatrix.http_artifact_read_hardening as artifact_hardening
from psmatrix import http_mcp
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPArtifactReadIdentityTests(unittest.TestCase):
    def _prepared(self, root: Path, payload: bytes = b"verified-artifact"):
        store = ProjectSessionStore(root / "home")
        record = store.create("principal")
        relative = ".psmatrix/mcp/report.json"
        store.upload(record, relative, payload)
        prepared = store.prepare_artifact(record, relative, purpose="diagnostic")
        token = prepared["downloadPath"].split("/artifacts/", 1)[1]
        return store, record, relative, token, payload

    def test_install_routes_artifact_gets_through_hardened_reader(self):
        self.assertTrue(getattr(http_mcp, "_artifact_read_boundary_hardened", False))
        self.assertIs(http_mcp.PSMatrixHTTPRequestHandler.do_GET, artifact_hardening._hardened_do_get)
        self.assertTrue(hasattr(ProjectSessionStore, "open_verified_artifact"))

    def test_content_swap_after_capability_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record, relative, token, _payload = self._prepared(Path(temp))
            target = record.root / relative
            original_resolve = store.resolve_artifact

            def resolve_then_swap(value: str, principal: str):
                result = original_resolve(value, principal)
                target.write_bytes(b"replacement-after-validation")
                return result

            with mock.patch.object(store, "resolve_artifact", side_effect=resolve_then_swap):
                with self.assertRaises(SessionError):
                    with store.open_verified_artifact(token, "principal"):
                        pass

    def test_verified_snapshot_is_stable_after_visible_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record, relative, token, payload = self._prepared(Path(temp))
            target = record.root / relative
            replacement = record.root / "replacement.bin"
            replacement.write_bytes(b"untrusted-replacement")

            with store.open_verified_artifact(token, "principal") as artifact:
                os.replace(replacement, target)
                self.assertEqual(artifact.size, len(payload))
                self.assertEqual(artifact.read(), payload)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow semantics")
    def test_symlink_swap_after_capability_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record, relative, token, _payload = self._prepared(Path(temp))
            target = record.root / relative
            outside = Path(temp) / "outside.bin"
            outside.write_bytes(b"verified-artifact")
            original_resolve = store.resolve_artifact

            def resolve_then_swap(value: str, principal: str):
                result = original_resolve(value, principal)
                target.unlink()
                target.symlink_to(outside)
                return result

            with mock.patch.object(store, "resolve_artifact", side_effect=resolve_then_swap):
                with self.assertRaises(SessionError):
                    with store.open_verified_artifact(token, "principal"):
                        pass

    @unittest.skipUnless(os.name == "posix", "POSIX hard-link semantics")
    def test_hardlink_swap_after_capability_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, record, relative, token, payload = self._prepared(Path(temp))
            target = record.root / relative
            outside = Path(temp) / "outside.bin"
            outside.write_bytes(payload)
            original_resolve = store.resolve_artifact

            def resolve_then_swap(value: str, principal: str):
                result = original_resolve(value, principal)
                target.unlink()
                os.link(outside, target)
                return result

            with mock.patch.object(store, "resolve_artifact", side_effect=resolve_then_swap):
                with self.assertRaises(SessionError):
                    with store.open_verified_artifact(token, "principal"):
                        pass


if __name__ == "__main__":
    unittest.main()
