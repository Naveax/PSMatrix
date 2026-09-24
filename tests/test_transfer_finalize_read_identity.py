import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_finalize_read_hardening as hardening


class TransferFinalizeReadIdentityTests(unittest.TestCase):
    def _store_with_chunk(self, root: Path):
        data = b"f" * 65536
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
        return store, transfer_id, digest, data

    def test_finalize_assembles_verified_chunks(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._store_with_chunk(Path(temp))
            result = store.finalize(transfer_id, controller_id="controller-a")
            self.assertTrue(result["complete"])
            self.assertEqual((store.objects / digest).read_bytes(), data)
            self.assertTrue((store.sessions / transfer_id / "complete.json").is_file())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_session_replacement_during_chunk_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, _, data = self._store_with_chunk(Path(temp))
            session = store.sessions / transfer_id
            renamed = store.sessions / f".{transfer_id}.original"
            replacement = store.sessions / transfer_id
            from psmatrix import transfer_chunk_write_hardening as chunk_hardening

            original_read = chunk_hardening._read_fd_exact
            swapped = False

            def replacing_read(module, fd, expected_size):
                nonlocal swapped
                raw = original_read(module, fd, expected_size)
                if not swapped:
                    swapped = True
                    session.rename(renamed)
                    replacement.mkdir()
                    (replacement / "chunks").mkdir()
                    (replacement / "manifest.json").write_bytes(
                        (renamed / "manifest.json").read_bytes()
                    )
                    (replacement / "chunks" / "00000000.bin").write_bytes(b"x" * len(data))
                return raw

            with patch.object(chunk_hardening, "_read_fd_exact", side_effect=replacing_read):
                with self.assertRaises(transfer.TransferError):
                    store.finalize(transfer_id, controller_id="controller-a")

            self.assertTrue(swapped)
            self.assertEqual((renamed / "chunks" / "00000000.bin").read_bytes(), data)
            self.assertEqual((replacement / "chunks" / "00000000.bin").read_bytes(), b"x" * len(data))

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_completion_refuses_replacement_session(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, _, _ = self._store_with_chunk(Path(temp))
            session = store.sessions / transfer_id
            renamed = store.sessions / f".{transfer_id}.original"
            replacement = store.sessions / transfer_id
            original_write = hardening._write_completion_for_session
            swapped = False

            def replacing_write(module, active_store, canonical, expected_session, value):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    session.rename(renamed)
                    replacement.mkdir()
                return original_write(
                    module,
                    active_store,
                    canonical,
                    expected_session,
                    value,
                )

            with patch.object(hardening, "_write_completion_for_session", side_effect=replacing_write):
                with self.assertRaises(transfer.TransferError):
                    store.finalize(transfer_id, controller_id="controller-a")

            self.assertTrue(swapped)
            self.assertFalse((replacement / "complete.json").exists())
            self.assertFalse((renamed / "complete.json").exists())

    def test_install_preserves_finalize_read_beneath_temp_object_wrapper(self):
        from psmatrix import transfer_temp_object_hardening as temp_hardening

        self.assertIs(transfer.TransferStore.finalize, temp_hardening._hardened_finalize)
        self.assertIs(temp_hardening._ORIGINAL_FINALIZE, hardening._hardened_finalize)
        self.assertTrue(
            getattr(transfer.TransferStore, "_finalize_read_identity_hardened", False)
        )


if __name__ == "__main__":
    unittest.main()
