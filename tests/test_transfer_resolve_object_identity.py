import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_resolve_object_hardening as hardening


class TransferResolveObjectIdentityTests(unittest.TestCase):
    def _completed_store(self, root: Path):
        data = b"r" * 65536
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
        store.finalize(transfer_id, controller_id="controller-a")
        return store, transfer_id, digest, data

    def test_resolve_reads_verified_content_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._completed_store(Path(temp))
            resolved = store.resolve(
                transfer_id,
                controller_id="controller-a",
                artifact_sha256=digest,
                artifact_size=len(data),
            )
            self.assertEqual(resolved, data)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_objects_root_replacement_during_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store, transfer_id, digest, data = self._completed_store(Path(temp))
            original_root = store.objects
            renamed = store.root / ".objects.original"
            replacement = store.objects
            original_read = hardening._read_fd_exact
            swapped = False

            def replacing_read(module, fd, expected_size, *, label):
                nonlocal swapped
                raw = original_read(module, fd, expected_size, label=label)
                if not swapped:
                    swapped = True
                    original_root.rename(renamed)
                    replacement.mkdir()
                    (replacement / digest).write_bytes(b"x" * len(data))
                return raw

            with patch.object(hardening, "_read_fd_exact", side_effect=replacing_read):
                with self.assertRaises(transfer.TransferError):
                    store.resolve(
                        transfer_id,
                        controller_id="controller-a",
                        artifact_sha256=digest,
                        artifact_size=len(data),
                    )

            self.assertTrue(swapped)
            self.assertEqual((renamed / digest).read_bytes(), data)
            self.assertEqual((replacement / digest).read_bytes(), b"x" * len(data))

    def test_install_replaces_only_resolve(self):
        self.assertIs(transfer.TransferStore.resolve, hardening._hardened_resolve)
        self.assertTrue(
            getattr(transfer.TransferStore, "_resolve_object_identity_hardened", False)
        )


if __name__ == "__main__":
    unittest.main()
