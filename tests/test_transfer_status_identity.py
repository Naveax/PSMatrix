import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_status_hardening as hardening


class TransferStatusIdentityTests(unittest.TestCase):
    def _store_with_chunk(self, root: Path):
        data = b"s" * 65536
        digest = hashlib.sha256(data).hexdigest()
        store = transfer.TransferStore(root / "store")
        created = store.create(
            controller_id="controller-a",
            artifact_sha256=digest,
            artifact_size=len(data),
            chunk_size=len(data),
            ttl_seconds=3600,
        )
        transfer_id = str(created["transfer_id"])
        store.put_chunk(
            transfer_id,
            0,
            data,
            chunk_sha256=digest,
            controller_id="controller-a",
        )
        return store, transfer_id

    def test_status_preserves_present_missing_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id = self._store_with_chunk(Path(temp))
            status = store.status(transfer_id, controller_id="controller-a")
            self.assertEqual(status["present"], [0])
            self.assertEqual(status["missing"], [])
            self.assertFalse(status["complete"])

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_session_replacement_during_status_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id = self._store_with_chunk(Path(temp))
            session = store.sessions / transfer_id
            renamed = store.sessions / f".{transfer_id}.original"
            replacement = store.sessions / transfer_id
            original_present = hardening._posix_file_present
            swapped = False

            def replacing_present(module, parent_fd, name, *, label):
                nonlocal swapped
                result = original_present(module, parent_fd, name, label=label)
                if not swapped and label == "Transfer chunk":
                    swapped = True
                    session.rename(renamed)
                    replacement.mkdir()
                    (replacement / "chunks").mkdir()
                    (replacement / "manifest.json").write_bytes(
                        (renamed / "manifest.json").read_bytes()
                    )
                    (replacement / "chunks" / "00000000.bin").write_bytes(b"x" * 65536)
                return result

            with patch.object(hardening, "_posix_file_present", side_effect=replacing_present):
                with self.assertRaises(transfer.TransferError):
                    store.status(transfer_id, controller_id="controller-a")

            self.assertTrue(swapped)
            self.assertTrue((renamed / "chunks" / "00000000.bin").is_file())
            self.assertTrue((replacement / "chunks" / "00000000.bin").is_file())

    def test_install_replaces_only_status(self):
        self.assertIs(transfer.TransferStore.status, hardening._hardened_status)
        self.assertTrue(getattr(transfer.TransferStore, "_status_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
