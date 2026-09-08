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

    def test_mirror_revalidates_mirror_file_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            self.assertTrue(queue.mirror_path.is_file())
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue.mirror_path)):
                with self.assertRaises(FleetQueueError):
                    queue.mirror()

    def test_write_mirror_revalidates_lock_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            self.assertTrue(queue.mirror_lock.is_file())
            with patch("pathlib.Path.lstat", new=_reparse_lstat(queue.mirror_lock)):
                with self.assertRaises(FleetQueueError):
                    queue._write_mirror()


if __name__ == "__main__":
    unittest.main()
