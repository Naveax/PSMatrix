import hashlib
import tempfile
import unittest
from pathlib import Path

from psmatrix.transfer import TransferError, TransferStore


class TransferRootIdentityTests(unittest.TestCase):
    def test_direct_objects_directory_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"
            store = TransferStore(root)
            raw = b"identity-bound-transfer"
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            original_objects = root / "objects-original"
            store.objects.replace(original_objects)
            store.objects.mkdir()

            with self.assertRaisesRegex(TransferError, "changed after initialization"):
                store.status(created["transfer_id"], controller_id="controller-a")

            self.assertTrue(original_objects.is_dir())
            self.assertEqual(list(store.objects.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
