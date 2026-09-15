import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_manifest_read_hardening as hardening


class TransferManifestReadIdentityTests(unittest.TestCase):
    def _store_with_manifest(self, root: Path):
        store = transfer.TransferStore(root / "store")
        created = store.create(
            controller_id="controller-a",
            artifact_sha256="a" * 64,
            artifact_size=65536,
            chunk_size=65536,
            ttl_seconds=3600,
        )
        return store, str(created["transfer_id"])

    def test_real_manifest_read_preserves_canonical_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id = self._store_with_manifest(Path(temp))
            manifest = store._load_manifest(transfer_id, controller_id="controller-a")
            self.assertEqual(manifest["transfer_id"], transfer_id)
            self.assertEqual(manifest["artifact_sha256"], "a" * 64)
            with self.assertRaises(transfer.TransferError):
                store._load_manifest(transfer_id, controller_id="controller-b")

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_session_replacement_during_manifest_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id = self._store_with_manifest(Path(temp))
            session = store.sessions / transfer_id
            renamed = store.sessions / f".{transfer_id}.original"
            replacement = store.sessions / transfer_id
            original_read = hardening._read_file_fd
            swapped = False

            def replacing_read(module, fd, *, label):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    session.rename(renamed)
                    replacement.mkdir()
                    (replacement / "manifest.json").write_bytes(
                        (renamed / "manifest.json").read_bytes()
                    )
                return original_read(module, fd, label=label)

            with patch.object(hardening, "_read_file_fd", side_effect=replacing_read):
                with self.assertRaises(transfer.TransferError):
                    store._load_manifest(transfer_id, controller_id="controller-a")

            self.assertTrue(swapped)
            self.assertTrue((renamed / "manifest.json").is_file())
            self.assertTrue((replacement / "manifest.json").is_file())

    @unittest.skipUnless(os.name == "nt", "Windows share-mode regression")
    def test_windows_manifest_pin_blocks_rename_during_read(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id = self._store_with_manifest(Path(temp))
            manifest = store.sessions / transfer_id / "manifest.json"
            moved = manifest.with_suffix(".moved")
            original_read = transfer._read_direct_file
            rename_blocked = False

            def checking_read(path, *, label, max_bytes=None):
                nonlocal rename_blocked
                try:
                    manifest.rename(moved)
                except OSError:
                    rename_blocked = True
                return original_read(path, label=label, max_bytes=max_bytes)

            with patch.object(transfer, "_read_direct_file", side_effect=checking_read):
                value = store._load_manifest(transfer_id, controller_id="controller-a")

            self.assertTrue(rename_blocked)
            self.assertEqual(value["transfer_id"], transfer_id)
            self.assertTrue(manifest.is_file())
            self.assertFalse(moved.exists())

    def test_install_replaces_only_manifest_loader(self):
        self.assertIs(transfer.TransferStore._load_manifest, hardening._hardened_load_manifest)
        self.assertTrue(
            getattr(transfer.TransferStore, "_manifest_read_identity_hardened", False)
        )


if __name__ == "__main__":
    unittest.main()
