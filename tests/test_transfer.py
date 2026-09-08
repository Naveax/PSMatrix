import hashlib
import tempfile
import unittest
from pathlib import Path

from psmatrix.transfer import TransferError, TransferStore


class TransferTests(unittest.TestCase):
    def _symlink_or_skip(self, target: Path, link: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Symlinks unavailable on this platform: {exc}")

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

    def test_transfer_store_rejects_symlink_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real_root = base / "real"
            real_root.mkdir()
            link_root = base / "linked"
            self._symlink_or_skip(real_root, link_root, directory=True)
            with self.assertRaises(TransferError):
                TransferStore(link_root)

    def test_transfer_store_rejects_symlink_parent_component(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            self._symlink_or_skip(real_parent, linked_parent, directory=True)
            with self.assertRaises(TransferError):
                TransferStore(linked_parent / "store")

    def test_transfer_rejects_indirect_session_and_chunk_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            raw = b"x" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            transfer_id = created["transfer_id"]
            session = store.sessions / transfer_id
            direct_session = base / "direct-session"
            session.rename(direct_session)
            self._symlink_or_skip(direct_session, session, directory=True)
            with self.assertRaises(TransferError):
                store.status(transfer_id, controller_id="controller-a")

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            raw = b"x" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            transfer_id = created["transfer_id"]
            chunks = store.sessions / transfer_id / "chunks"
            direct_chunks = base / "direct-chunks"
            chunks.rename(direct_chunks)
            self._symlink_or_skip(direct_chunks, chunks, directory=True)
            with self.assertRaises(TransferError):
                store.status(transfer_id, controller_id="controller-a")

    def test_transfer_rejects_indirect_manifest_and_object_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            raw = b"x" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            transfer_id = created["transfer_id"]
            manifest = store.sessions / transfer_id / "manifest.json"
            direct_manifest = base / "manifest.json"
            manifest.rename(direct_manifest)
            self._symlink_or_skip(direct_manifest, manifest)
            with self.assertRaises(TransferError):
                store.status(transfer_id, controller_id="controller-a")

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            raw = b"x" * (64 * 1024)
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
            external = base / "external-object"
            external.write_bytes(raw)
            object_path = store.objects / digest
            self._symlink_or_skip(external, object_path)
            with self.assertRaises(TransferError):
                store.finalize(created["transfer_id"], controller_id="controller-a")

    def test_purge_rejects_indirect_session_path(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            raw = b"x" * (64 * 1024)
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
                ttl_seconds=60,
            )
            session = store.sessions / created["transfer_id"]
            direct_session = base / "expired-session"
            session.rename(direct_session)
            self._symlink_or_skip(direct_session, session, directory=True)
            with self.assertRaises(TransferError):
                store.purge_expired()

    def test_transfer_rejects_indirect_internal_directories_and_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            direct_sessions = base / "direct-sessions"
            store.sessions.rename(direct_sessions)
            self._symlink_or_skip(direct_sessions, store.sessions, directory=True)
            raw = b"x" * (64 * 1024)
            with self.assertRaises(TransferError):
                store.create(
                    controller_id="controller-a",
                    artifact_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_size=len(raw),
                    chunk_size=64 * 1024,
                )

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = TransferStore(base / "store")
            external_lock = base / "external-lock"
            external_lock.write_bytes(b"")
            self._symlink_or_skip(external_lock, store.lock_path)
            raw = b"x" * (64 * 1024)
            with self.assertRaises(TransferError):
                store.create(
                    controller_id="controller-a",
                    artifact_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_size=len(raw),
                    chunk_size=64 * 1024,
                )


if __name__ == "__main__":
    unittest.main()
