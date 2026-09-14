import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_temp_object_hardening as hardening


class TransferTemporaryObjectIdentityTests(unittest.TestCase):
    def _store_with_chunk(self, root: Path):
        data = b"t" * transfer._MIN_CHUNK
        digest = hashlib.sha256(data).hexdigest()
        store = transfer.TransferStore(root / "store")
        created = store.create(
            controller_id="controller-a",
            artifact_sha256=digest,
            artifact_size=len(data),
            chunk_size=transfer._MIN_CHUNK,
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

    def test_finalize_publishes_verified_object_and_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._store_with_chunk(Path(temp))
            result = store.finalize(transfer_id, controller_id="controller-a")
            self.assertTrue(result["complete"])
            self.assertEqual((store.objects / digest).read_bytes(), data)
            self.assertTrue((store.sessions / transfer_id / "complete.json").is_file())
            self.assertFalse(any(item.name.endswith(".tmp") for item in store.objects.iterdir()))

    def test_finalize_reuses_existing_verified_content_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._store_with_chunk(Path(temp))
            (store.objects / digest).write_bytes(data)
            result = store.finalize(transfer_id, controller_id="controller-a")
            self.assertTrue(result["complete"])
            self.assertEqual((store.objects / digest).read_bytes(), data)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_objects_root_swap_after_temp_verification_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store, transfer_id, digest, _ = self._store_with_chunk(root)
            original_objects = store.objects
            moved = store.root / ".objects.original"
            replacement = store.root / ".objects.replacement"
            replacement.mkdir()
            sentinel = replacement / "sentinel.txt"
            sentinel.write_text("replacement", encoding="utf-8")
            swapped = False

            def swap_objects(active_store, temporary):
                nonlocal swapped
                if swapped:
                    return
                swapped = True
                original_objects.rename(moved)
                replacement.rename(original_objects)

            with patch.object(hardening, "_after_temp_verified", side_effect=swap_objects):
                with self.assertRaises(transfer.TransferError):
                    store.finalize(transfer_id, controller_id="controller-a")

            self.assertTrue(swapped)
            self.assertEqual(
                (original_objects / "sentinel.txt").read_text(encoding="utf-8"),
                "replacement",
            )
            self.assertFalse((original_objects / digest).exists())
            self.assertFalse(any(item.name.endswith(".tmp") for item in moved.iterdir()))

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_no_overwrite_publication_rejects_corrupt_existing_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._store_with_chunk(Path(temp))
            (store.objects / digest).write_bytes(b"x" * len(data))
            with self.assertRaises(transfer.TransferError):
                store.finalize(transfer_id, controller_id="controller-a")
            self.assertEqual((store.objects / digest).read_bytes(), b"x" * len(data))
            self.assertFalse((store.sessions / transfer_id / "complete.json").exists())

    def test_install_wires_finalize(self):
        self.assertIs(transfer.TransferStore.finalize, hardening._hardened_finalize)
        self.assertTrue(getattr(transfer.TransferStore, "_temp_object_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
