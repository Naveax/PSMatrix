import hashlib
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.transfer import TransferError, TransferStore


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if Path(path) in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class TransferPathSecurityTests(unittest.TestCase):
    def test_store_rejects_intermediate_symlink_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink unavailable: {exc}")

            with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                TransferStore(alias / "store")

    def test_store_rejects_simulated_reparse_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {root})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    TransferStore(root)

    def test_store_rejects_simulated_intermediate_reparse_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            state = base / "state"
            state.mkdir()
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {state})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    TransferStore(state / "store")

    def test_unknown_transfer_preserves_lookup_error(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            with self.assertRaisesRegex(TransferError, "Unknown transfer ID"):
                store.status(str(uuid.uuid4()), controller_id="controller-a")

    def test_create_revalidates_lock_file(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            store.lock_path.write_bytes(b"")
            raw = b"z" * (64 * 1024)
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {store.lock_path})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.create(
                        controller_id="controller-a",
                        artifact_sha256=hashlib.sha256(raw).hexdigest(),
                        artifact_size=len(raw),
                        chunk_size=64 * 1024,
                    )

    def test_put_chunk_revalidates_sessions_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"a" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {store.sessions})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.put_chunk(
                        created["transfer_id"],
                        0,
                        raw,
                        chunk_sha256=hashlib.sha256(raw).hexdigest(),
                        controller_id="controller-a",
                    )

            target = store.sessions / created["transfer_id"] / "chunks" / "00000000.bin"
            self.assertFalse(target.exists())

    def test_status_rejects_reparse_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"b" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            manifest = store.sessions / created["transfer_id"] / "manifest.json"
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {manifest})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.status(created["transfer_id"], controller_id="controller-a")

    def test_finalize_revalidates_objects_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"o" * (64 * 1024)
            digest = hashlib.sha256(raw).hexdigest()
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=digest,
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            store.put_chunk(
                created["transfer_id"],
                0,
                raw,
                chunk_sha256=digest,
                controller_id="controller-a",
            )

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {store.objects})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.finalize(created["transfer_id"], controller_id="controller-a")

    def test_finalize_rejects_reparse_existing_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"c" * (64 * 1024)
            digest = hashlib.sha256(raw).hexdigest()
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=digest,
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            store.put_chunk(
                created["transfer_id"],
                0,
                raw,
                chunk_sha256=digest,
                controller_id="controller-a",
            )
            object_path = store.objects / digest
            object_path.write_bytes(raw)

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {object_path})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.finalize(created["transfer_id"], controller_id="controller-a")

    def test_purge_expired_rejects_indirect_session_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp))
            raw = b"d" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            session = store.sessions / created["transfer_id"]
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {session})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse point"):
                    store.purge_expired()


if __name__ == "__main__":
    unittest.main()
