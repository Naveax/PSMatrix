import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import signing_publish_hardening as signing_publish
from psmatrix import transfer
from psmatrix import transfer_publish_hardening as hardening


class TransferPublishBoundaryTests(unittest.TestCase):
    def test_transfer_store_manifest_and_chunk_use_hardened_publishers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"
            store = transfer.TransferStore(root)
            data = b"x" * (64 * 1024)
            digest = hashlib.sha256(data).hexdigest()

            created = store.create(
                controller_id="controller-1",
                artifact_sha256=digest,
                artifact_size=len(data),
                chunk_size=len(data),
                ttl_seconds=60,
            )
            status = store.put_chunk(
                created["transfer_id"],
                0,
                data,
                chunk_sha256=digest,
                controller_id="controller-1",
            )

            self.assertEqual(status["present"], [0])
            session = store.sessions / created["transfer_id"]
            self.assertTrue((session / "manifest.json").is_file())
            self.assertTrue((session / "chunks" / "00000000.bin").is_file())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_parent_replacement_during_transfer_publish_fails_without_redirect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "chunks"
            parent.mkdir()
            target = parent / "00000000.bin"
            moved = root / "chunks-original"
            original_replace = os.replace

            def swap_parent_then_replace(src, dst, *args, **kwargs):
                parent.rename(moved)
                parent.mkdir()
                return original_replace(src, dst, *args, **kwargs)

            with patch.object(
                signing_publish.os,
                "replace",
                side_effect=swap_parent_then_replace,
            ):
                with self.assertRaisesRegex(transfer.TransferError, "parent identity changed"):
                    hardening._hardened_atomic_write_bytes(target, b"trusted")

            self.assertFalse(target.exists())
            self.assertFalse((moved / "00000000.bin").exists())

    def test_missing_transfer_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "missing" / "manifest.json"
            with self.assertRaises(transfer.TransferError):
                hardening._hardened_atomic_write_json(target, {"schema": 1})
            self.assertFalse(target.exists())

    def test_install_wires_transfer_atomic_publishers(self):
        self.assertIs(transfer.atomic_write_bytes, hardening._hardened_atomic_write_bytes)
        self.assertIs(transfer.atomic_write_json, hardening._hardened_atomic_write_json)


if __name__ == "__main__":
    unittest.main()
