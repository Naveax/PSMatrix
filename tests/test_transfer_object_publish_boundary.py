import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_object_publish_hardening as hardening


class TransferObjectPublishBoundaryTests(unittest.TestCase):
    def _one_chunk_store(self, root: Path):
        store = transfer.TransferStore(root)
        data = b"artifact" * (64 * 1024 // len(b"artifact"))
        if len(data) < 64 * 1024:
            data += b"x" * (64 * 1024 - len(data))
        digest = hashlib.sha256(data).hexdigest()
        created = store.create(
            controller_id="controller-1",
            artifact_sha256=digest,
            artifact_size=len(data),
            chunk_size=len(data),
            ttl_seconds=60,
        )
        store.put_chunk(
            created["transfer_id"],
            0,
            data,
            chunk_sha256=digest,
            controller_id="controller-1",
        )
        return store, created["transfer_id"], data, digest

    def test_finalize_publishes_verified_content_addressed_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, data, digest = self._one_chunk_store(Path(temp) / "store")

            result = store.finalize(transfer_id, controller_id="controller-1")

            self.assertTrue(result["complete"])
            object_path = store.objects / digest
            self.assertEqual(object_path.read_bytes(), data)
            self.assertTrue(
                (store.sessions / transfer_id / "complete.json").is_file()
            )

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_parent_replacement_during_object_publish_fails_without_redirect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            objects = root / "objects"
            objects.mkdir()
            temporary = objects / ".object.tmp"
            target = objects / "object"
            temporary.write_bytes(b"trusted")
            moved = root / "objects-original"
            original_replace = os.replace

            def swap_parent_then_replace(src, dst, *args, **kwargs):
                objects.rename(moved)
                objects.mkdir()
                return original_replace(src, dst, *args, **kwargs)

            with patch.object(hardening.os, "replace", side_effect=swap_parent_then_replace):
                with self.assertRaisesRegex(transfer.TransferError, "parent identity changed"):
                    hardening._publish_existing_posix(
                        transfer,
                        temporary,
                        target,
                        label="Transfer content object",
                    )

            self.assertFalse(target.exists())
            self.assertFalse((moved / "object").exists())

    def test_existing_verified_object_is_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, data, digest = self._one_chunk_store(Path(temp) / "store")
            first = store.finalize(transfer_id, controller_id="controller-1")
            second = store.finalize(transfer_id, controller_id="controller-1")

            self.assertTrue(first["complete"])
            self.assertTrue(second["complete"])
            self.assertEqual((store.objects / digest).read_bytes(), data)

    def test_install_wires_transfer_finalize(self):
        self.assertIs(transfer.TransferStore.finalize, hardening._hardened_finalize)


if __name__ == "__main__":
    unittest.main()
