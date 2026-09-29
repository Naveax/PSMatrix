import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_chunk_write_hardening as hardening


class TransferChunkWriteIdentityTests(unittest.TestCase):
    def _store(self, root: Path):
        store = transfer.TransferStore(root / "store")
        payload = b"x" * 65536
        created = store.create(
            controller_id="controller-a",
            artifact_sha256=hashlib.sha256(payload).hexdigest(),
            artifact_size=len(payload),
            chunk_size=len(payload),
            ttl_seconds=3600,
        )
        return store, str(created["transfer_id"]), payload

    def test_put_chunk_accepts_idempotent_same_bytes_and_rejects_different_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, payload = self._store(Path(temp))
            digest = hashlib.sha256(payload).hexdigest()
            first = store.put_chunk(
                transfer_id,
                0,
                payload,
                chunk_sha256=digest,
                controller_id="controller-a",
            )
            second = store.put_chunk(
                transfer_id,
                0,
                payload,
                chunk_sha256=digest,
                controller_id="controller-a",
            )
            self.assertEqual(first["present"], [0])
            self.assertEqual(second["present"], [0])

            other = b"y" * len(payload)
            with self.assertRaises(transfer.TransferError):
                store.put_chunk(
                    transfer_id,
                    0,
                    other,
                    chunk_sha256=hashlib.sha256(other).hexdigest(),
                    controller_id="controller-a",
                )

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_chunks_directory_replacement_during_publish_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, payload = self._store(Path(temp))
            session = store.sessions / transfer_id
            chunks = session / "chunks"
            original = session / ".chunks-original"
            replacement = session / "chunks"
            real_write_all = hardening._write_all
            swapped = False

            def replacing_write(fd, data):
                nonlocal swapped
                real_write_all(fd, data)
                if not swapped:
                    swapped = True
                    chunks.rename(original)
                    replacement.mkdir()

            with patch.object(hardening, "_write_all", side_effect=replacing_write):
                with self.assertRaises(transfer.TransferError):
                    store.put_chunk(
                        transfer_id,
                        0,
                        payload,
                        chunk_sha256=hashlib.sha256(payload).hexdigest(),
                        controller_id="controller-a",
                    )

            self.assertTrue(swapped)
            self.assertFalse((replacement / "00000000.bin").exists())

    @unittest.skipUnless(os.name == "nt", "Windows directory pin regression")
    def test_windows_chunks_directory_cannot_be_renamed_while_chunk_is_written(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, payload = self._store(Path(temp))
            chunks = store.sessions / transfer_id / "chunks"
            moved = chunks.with_name("chunks-moved")
            real_write_all = hardening._write_all
            rename_blocked = False

            def checking_write(fd, data):
                nonlocal rename_blocked
                try:
                    chunks.rename(moved)
                except OSError:
                    rename_blocked = True
                return real_write_all(fd, data)

            with patch.object(hardening, "_write_all", side_effect=checking_write):
                result = store.put_chunk(
                    transfer_id,
                    0,
                    payload,
                    chunk_sha256=hashlib.sha256(payload).hexdigest(),
                    controller_id="controller-a",
                )

            self.assertTrue(rename_blocked)
            self.assertEqual(result["present"], [0])
            self.assertTrue((chunks / "00000000.bin").is_file())
            self.assertFalse(moved.exists())

    def test_install_replaces_only_put_chunk(self):
        self.assertIs(transfer.TransferStore.put_chunk, hardening._hardened_put_chunk)
        self.assertTrue(
            getattr(transfer.TransferStore, "_chunk_write_identity_hardened", False)
        )


if __name__ == "__main__":
    unittest.main()
