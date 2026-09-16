import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_create_reuse_hardening as hardening


class TransferCreateReuseIdentityTests(unittest.TestCase):
    def _create(self, store: transfer.TransferStore, data: bytes):
        return store.create(
            controller_id="controller-a",
            artifact_sha256=hashlib.sha256(data).hexdigest(),
            artifact_size=len(data),
            chunk_size=transfer._MIN_CHUNK,
            ttl_seconds=3600,
        )

    def test_matching_active_transfer_is_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            data = b"r" * transfer._MIN_CHUNK
            first = self._create(store, data)
            second = self._create(store, data)
            self.assertEqual(second["transfer_id"], first["transfer_id"])
            self.assertEqual(second["present"], [])
            self.assertEqual(second["missing"], [0])
            self.assertFalse(second["complete"])

    def test_matching_transfer_reuse_reports_existing_chunk(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            data = b"c" * transfer._MIN_CHUNK
            first = self._create(store, data)
            digest = hashlib.sha256(data).hexdigest()
            store.put_chunk(
                first["transfer_id"],
                0,
                data,
                chunk_sha256=digest,
                controller_id="controller-a",
            )
            reused = self._create(store, data)
            self.assertEqual(reused["transfer_id"], first["transfer_id"])
            self.assertEqual(reused["present"], [0])
            self.assertEqual(reused["missing"], [])
            self.assertFalse(reused["complete"])

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_matching_reuse_decision_cannot_switch_to_replacement_session(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            data = b"x" * transfer._MIN_CHUNK
            first = self._create(store, data)
            session = store.sessions / first["transfer_id"]
            moved = store.sessions / f".{session.name}.original"
            replacement = store.sessions / session.name
            original_matches = hardening._matches_request
            swapped = False

            def swap_after_match(module, manifest, **kwargs):
                nonlocal swapped
                result = original_matches(module, manifest, **kwargs)
                if result and not swapped:
                    swapped = True
                    session.rename(moved)
                    replacement.mkdir()
                    (replacement / "chunks").mkdir()
                    (replacement / "manifest.json").write_bytes(
                        (moved / "manifest.json").read_bytes()
                    )
                return result

            with patch.object(hardening, "_matches_request", side_effect=swap_after_match):
                with self.assertRaises(transfer.TransferError):
                    self._create(store, data)

            self.assertTrue(swapped)
            self.assertTrue((moved / "manifest.json").is_file())
            self.assertTrue((replacement / "manifest.json").is_file())

    def test_install_wires_create_reuse_boundary(self):
        self.assertIs(transfer.TransferStore.create, hardening._hardened_create)
        self.assertTrue(
            getattr(transfer.TransferStore, "_create_reuse_identity_hardened", False)
        )


if __name__ == "__main__":
    unittest.main()
