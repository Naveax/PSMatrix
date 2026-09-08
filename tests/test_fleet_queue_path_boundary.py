import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.fleet_queue import FleetQueue, FleetQueueError


_REPARSE_POINT = 0x400


def _reparse_lstat(target: Path):
    original = Path.lstat
    wanted = Path(os.path.abspath(os.fspath(target)))

    def fake(path: Path):
        info = original(path)
        current = Path(os.path.abspath(os.fspath(path)))
        if current == wanted:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class FleetQueuePathBoundaryTests(unittest.TestCase):
    def test_constructor_rejects_reparse_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "state"
            root.mkdir()
            queue_path = root / "queue.sqlite3"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(root)):
                with self.assertRaises(FleetQueueError):
                    FleetQueue(queue_path)

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_constructor_rejects_real_intermediate_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(FleetQueueError, "symlink or reparse"):
                FleetQueue(alias / "queue.sqlite3")
            self.assertEqual(list(real.iterdir()), [])

    def test_constructor_rejects_hardlinked_database_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.sqlite3"
            FleetQueue(source)
            alias = root / "alias.sqlite3"
            try:
                os.link(source, alias)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(FleetQueueError, "direct regular file"):
                FleetQueue(alias)

    def test_recovery_handle_rejects_reparse_database(self):
        with tempfile.TemporaryDirectory() as temp:
            queue_path = Path(temp) / "queue.sqlite3"
            FleetQueue(queue_path)
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue_path)):
                with self.assertRaises(FleetQueueError):
                    FleetQueue.recovery_handle(queue_path)

    def test_connect_revalidates_database_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue.path)):
                with self.assertRaises(FleetQueueError):
                    queue.list()

    def test_connect_rejects_direct_database_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            original = Path(temp) / "original.sqlite3"
            queue.path.replace(original)
            queue.path.write_bytes(original.read_bytes())
            with self.assertRaisesRegex(FleetQueueError, "changed after initialization"):
                queue.list()

    def test_connect_rejects_reparse_sqlite_sidecar_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            wal = queue.path.with_name(queue.path.name + "-wal")
            wal.write_bytes(b"")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(wal)):
                with patch("psmatrix.fleet_queue.sqlite3.connect") as connect:
                    with self.assertRaises(FleetQueueError):
                        queue._connect()
                    connect.assert_not_called()

    def test_connect_rejects_hardlinked_sqlite_sidecar_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            wal = queue.path.with_name(queue.path.name + "-wal")
            peer = Path(temp) / "peer-wal"
            peer.write_bytes(b"")
            try:
                os.link(peer, wal)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with patch("psmatrix.fleet_queue.sqlite3.connect") as connect:
                with self.assertRaisesRegex(FleetQueueError, "direct regular file"):
                    queue._connect()
                connect.assert_not_called()
            self.assertEqual(peer.read_bytes(), b"")

    def test_mirror_revalidates_mirror_file_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            self.assertTrue(queue.mirror_path.is_file())
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue.mirror_path)):
                with self.assertRaises(FleetQueueError):
                    queue.mirror()

    def test_mirror_rejects_hardlink_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            peer = Path(temp) / "mirror-peer.json"
            try:
                os.link(queue.mirror_path, peer)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(FleetQueueError, "direct regular file"):
                queue.mirror()

    def test_write_mirror_revalidates_lock_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            self.assertTrue(queue.mirror_lock.is_file())
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue.mirror_lock)):
                with self.assertRaises(FleetQueueError):
                    queue._write_mirror()

    def test_write_mirror_rejects_hardlinked_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            peer = Path(temp) / "lock-peer"
            try:
                os.link(queue.mirror_lock, peer)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(FleetQueueError, "direct regular file"):
                queue._write_mirror()


if __name__ == "__main__":
    unittest.main()
