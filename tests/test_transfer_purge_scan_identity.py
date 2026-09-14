import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_purge_scan_hardening as hardening


class TransferPurgeScanIdentityTests(unittest.TestCase):
    def _expired_by_missing_manifest(self, root: Path):
        store = transfer.TransferStore(root)
        data = b"purge-scan"
        created = store.create(
            controller_id="controller-1",
            artifact_sha256=transfer._sha256_bytes(data),
            artifact_size=len(data),
            chunk_size=transfer._MIN_CHUNK,
            ttl_seconds=60,
        )
        session = store.sessions / str(created["transfer_id"])
        (session / "manifest.json").unlink()
        return store, session

    def test_missing_manifest_session_is_purged(self):
        with tempfile.TemporaryDirectory() as temp:
            store, session = self._expired_by_missing_manifest(Path(temp) / "store")
            result = store.purge_expired()
            self.assertEqual(result, {"removed_sessions": 1})
            self.assertFalse(session.exists())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_purge_decision_cannot_be_redirected_to_replacement_session(self):
        with tempfile.TemporaryDirectory() as temp:
            store, session = self._expired_by_missing_manifest(Path(temp) / "store")
            moved = session.with_name(session.name + "-original")
            replacement = session.with_name(session.name + "-replacement")
            replacement.mkdir()
            (replacement / "sentinel.txt").write_text("replacement", encoding="utf-8")
            original_remove = hardening._remove_expected_session
            swapped = False

            def replacing_remove(module, active_store, candidate, expected_identity):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    session.rename(moved)
                    replacement.rename(session)
                return original_remove(
                    module,
                    active_store,
                    candidate,
                    expected_identity,
                )

            with patch.object(hardening, "_remove_expected_session", side_effect=replacing_remove):
                with self.assertRaises(transfer.TransferError):
                    store.purge_expired()

            self.assertTrue(swapped)
            self.assertTrue(moved.is_dir())
            self.assertEqual(
                (session / "sentinel.txt").read_text(encoding="utf-8"),
                "replacement",
            )
            self.assertFalse(any(".purge-" in item.name for item in store.sessions.iterdir()))

    def test_install_wires_purge_expired(self):
        self.assertIs(transfer.TransferStore.purge_expired, hardening._hardened_purge_expired)
        self.assertTrue(getattr(transfer.TransferStore, "_purge_scan_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
