import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.transfer as transfer_module
from psmatrix.transfer import TransferError, TransferStore


_REPARSE_POINT = 0x400


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reparse_lstat(targets: set[Path]):
    original = Path.lstat
    wanted = {_absolute(path) for path in targets}

    def fake(path: Path):
        info = original(path)
        if _absolute(path) in wanted:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=getattr(info, "st_size", 0),
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _raw() -> bytes:
    return b"transfer-path-security" * 4096


def _created(store: TransferStore, raw: bytes) -> dict:
    return store.create(
        controller_id="controller-a",
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
        artifact_size=len(raw),
        chunk_size=64 * 1024,
    )


def _upload_all(store: TransferStore, created: dict, raw: bytes) -> None:
    for index in created["missing"]:
        start = index * created["chunk_size"]
        chunk = raw[start : start + created["chunk_size"]]
        store.put_chunk(
            created["transfer_id"],
            index,
            chunk,
            chunk_sha256=hashlib.sha256(chunk).hexdigest(),
            controller_id="controller-a",
        )


class TransferPathSecurityTests(unittest.TestCase):
    def test_init_rejects_simulated_reparse_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"
            root.mkdir()
            with patch("pathlib.Path.lstat", new=_reparse_lstat({root})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                    TransferStore(root)
            self.assertEqual(list(root.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_init_rejects_posix_symlink_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                TransferStore(alias)
            self.assertEqual(list(real.iterdir()), [])

    def test_status_rejects_reparse_manifest_after_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            manifest = store.sessions / created["transfer_id"] / "manifest.json"
            with patch("pathlib.Path.lstat", new=_reparse_lstat({manifest})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                    store.status(created["transfer_id"], controller_id="controller-a")

    def test_put_chunk_rejects_reparse_existing_chunk(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            chunk = raw[: created["chunk_size"]]
            store.put_chunk(
                created["transfer_id"],
                0,
                chunk,
                chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                controller_id="controller-a",
            )
            target = store.sessions / created["transfer_id"] / "chunks" / "00000000.bin"
            with patch("pathlib.Path.lstat", new=_reparse_lstat({target})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                    store.put_chunk(
                        created["transfer_id"],
                        0,
                        chunk,
                        chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                        controller_id="controller-a",
                    )

    def test_put_chunk_rejects_hardlink_alias_without_touching_peer(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            chunk = raw[: created["chunk_size"]]
            target = store.sessions / created["transfer_id"] / "chunks" / "00000000.bin"
            peer = Path(temp) / "peer.bin"
            peer.write_bytes(chunk)
            try:
                os.link(peer, target)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(TransferError, "direct regular file"):
                store.put_chunk(
                    created["transfer_id"],
                    0,
                    chunk,
                    chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                    controller_id="controller-a",
                )
            self.assertEqual(peer.read_bytes(), chunk)

    def test_resolve_rejects_reparse_content_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            _upload_all(store, created, raw)
            store.finalize(created["transfer_id"], controller_id="controller-a")
            object_path = store.objects / hashlib.sha256(raw).hexdigest()
            with patch("pathlib.Path.lstat", new=_reparse_lstat({object_path})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                    store.resolve(
                        created["transfer_id"],
                        controller_id="controller-a",
                        artifact_sha256=hashlib.sha256(raw).hexdigest(),
                        artifact_size=len(raw),
                    )

    def test_resolve_rejects_hardlinked_content_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            _upload_all(store, created, raw)
            store.finalize(created["transfer_id"], controller_id="controller-a")
            object_path = store.objects / hashlib.sha256(raw).hexdigest()
            peer = Path(temp) / "peer.bin"
            try:
                os.link(object_path, peer)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(TransferError, "direct regular file"):
                store.resolve(
                    created["transfer_id"],
                    controller_id="controller-a",
                    artifact_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_size=len(raw),
                )
            self.assertEqual(peer.read_bytes(), raw)

    def test_store_roots_are_revalidated_at_use_time(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            with patch("pathlib.Path.lstat", new=_reparse_lstat({store.objects})):
                with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                    store.status(created["transfer_id"], controller_id="controller-a")

    def test_oversized_manifest_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            manifest = store.sessions / created["transfer_id"] / "manifest.json"
            manifest.write_bytes(
                b"x" * (transfer_module._MAX_METADATA_BYTES + 1)
            )
            with patch(
                "psmatrix.transfer.os.open",
                side_effect=AssertionError("oversized manifest must fail before os.open"),
            ) as open_mock:
                with self.assertRaisesRegex(TransferError, "size limit"):
                    store.status(
                        created["transfer_id"],
                        controller_id="controller-a",
                    )
                open_mock.assert_not_called()

    def test_put_chunk_rejects_oversized_existing_chunk(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            chunk = raw[: created["chunk_size"]]
            target = store.sessions / created["transfer_id"] / "chunks" / "00000000.bin"
            target.write_bytes(chunk + b"x")
            with self.assertRaisesRegex(TransferError, "size limit"):
                store.put_chunk(
                    created["transfer_id"],
                    0,
                    chunk,
                    chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                    controller_id="controller-a",
                )

    def test_resolve_rejects_oversized_content_object(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            raw = _raw()
            created = _created(store, raw)
            _upload_all(store, created, raw)
            store.finalize(created["transfer_id"], controller_id="controller-a")
            object_path = store.objects / hashlib.sha256(raw).hexdigest()
            object_path.write_bytes(raw + b"x")
            with self.assertRaisesRegex(TransferError, "size limit"):
                store.resolve(
                    created["transfer_id"],
                    controller_id="controller-a",
                    artifact_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_size=len(raw),
                )

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_purge_rejects_indirect_session_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TransferStore(Path(temp) / "store")
            external = Path(temp) / "external-session"
            external.mkdir()
            marker = external / "marker.txt"
            marker.write_text("keep\n", encoding="utf-8")
            alias = store.sessions / "00000000-0000-0000-0000-000000000000"
            alias.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(TransferError, "symlink or reparse"):
                store.purge_expired()
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
            self.assertTrue(alias.is_symlink())


if __name__ == "__main__":
    unittest.main()
