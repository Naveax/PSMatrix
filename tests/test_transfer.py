import hashlib
import tempfile
import unittest
from pathlib import Path

from psmatrix.transfer import TransferError, TransferStore


class TransferTests(unittest.TestCase):
    def test_resumable_transfer_is_idempotent_and_content_addressed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = (b"PSMatrix-transfer-" * 9000) + b"end"
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            duplicate = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            self.assertEqual(duplicate["transfer_id"], created["transfer_id"])
            transfer_id = created["transfer_id"]
            for index in reversed(created["missing"]):
                start = index * created["chunk_size"]
                chunk = raw[start:start + created["chunk_size"]]
                result = store.put_chunk(
                    transfer_id, index, chunk,
                    chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                    controller_id="controller-a",
                )
                self.assertNotIn(index, result["missing"])
            complete = store.finalize(transfer_id, controller_id="controller-a")
            self.assertTrue(complete["complete"])
            self.assertEqual(
                store.resolve(
                    transfer_id,
                    controller_id="controller-a",
                    artifact_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_size=len(raw),
                ), raw,
            )
            first = raw[:created["chunk_size"]]
            store.put_chunk(
                transfer_id, 0, first,
                chunk_sha256=hashlib.sha256(first).hexdigest(),
                controller_id="controller-a",
            )

    def test_transfer_rejects_wrong_controller_corruption_and_incomplete_finalize(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"a" * (64 * 1024 + 9)
            created = store.create(
                controller_id="controller-a", artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw), chunk_size=64 * 1024,
            )
            with self.assertRaises(TransferError):
                store.status(created["transfer_id"], controller_id="controller-b")
            with self.assertRaises(TransferError):
                store.finalize(created["transfer_id"], controller_id="controller-a")
            chunk = raw[:64 * 1024]
            with self.assertRaises(TransferError):
                store.put_chunk(
                    created["transfer_id"], 0, chunk,
                    chunk_sha256="0" * 64, controller_id="controller-a",
                )


if __name__ == "__main__":
    unittest.main()
