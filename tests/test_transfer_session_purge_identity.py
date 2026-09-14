import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_session_purge_hardening as hardening


class TransferSessionPurgeIdentityTests(unittest.TestCase):
    def _session(self, root: Path):
        store = transfer.TransferStore(root)
        data = b"purge-me"
        created = store.create(
            controller_id="controller-1",
            artifact_sha256=transfer._sha256_bytes(data),
            artifact_size=len(data),
            chunk_size=transfer._MIN_CHUNK,
            ttl_seconds=60,
        )
        session = store.sessions / created["transfer_id"]
        return store, session

    def test_real_remove_session_deletes_only_session_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            store, session = self._session(Path(temp) / "store")
            sibling = store.sessions / "keep"
            sibling.mkdir()
            (sibling / "keep.txt").write_text("keep", encoding="utf-8")

            store._remove_session(session)

            self.assertFalse(session.exists())
            self.assertEqual((sibling / "keep.txt").read_text(encoding="utf-8"), "keep")

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_session_swap_before_quarantine_fails_without_deleting_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            store, session = self._session(Path(temp) / "store")
            moved = session.with_name(session.name + "-original")
            replacement = session.with_name(session.name + "-replacement")
            replacement.mkdir()
            (replacement / "keep.txt").write_text("replacement", encoding="utf-8")
            real_replace = os.replace
            swapped = {"done": False}

            def race_replace(src, dst, *args, **kwargs):
                if not swapped["done"]:
                    swapped["done"] = True
                    session.rename(moved)
                    replacement.rename(session)
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(os, "replace", side_effect=race_replace):
                with self.assertRaises(transfer.TransferError):
                    store._remove_session(session)

            self.assertTrue((moved / "manifest.json").is_file())
            quarantines = [p for p in store.sessions.iterdir() if ".purge-" in p.name]
            self.assertEqual(len(quarantines), 1)
            self.assertEqual((quarantines[0] / "keep.txt").read_text(encoding="utf-8"), "replacement")

    @unittest.skipUnless(os.name == "nt", "Windows handle-delete regression")
    def test_windows_remove_session_uses_handle_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            store, session = self._session(Path(temp) / "store")
            store._remove_session(session)
            self.assertFalse(session.exists())
            self.assertFalse(any(".purge-" in p.name for p in store.sessions.iterdir()))

    def test_install_wires_remove_session(self):
        self.assertIs(transfer.TransferStore._remove_session, hardening._hardened_remove_session)


if __name__ == "__main__":
    unittest.main()
