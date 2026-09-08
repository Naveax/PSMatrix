import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.util import exclusive_lock


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=getattr(info, "st_size", 0),
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class UtilTests(unittest.TestCase):
    def test_exclusive_lock_can_be_acquired_released_and_reacquired(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / "locks" / "operation.lock"
            with exclusive_lock(lock):
                self.assertTrue(lock.is_file())
            with exclusive_lock(lock):
                self.assertTrue(lock.is_file())

    def test_exclusive_lock_rejects_simulated_reparse_final_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = root / "operation.lock"
            lock.write_bytes(b"existing")
            original_lstat = Path.lstat
            with patch.object(
                Path,
                "lstat",
                _reparse_lstat(original_lstat, {lock}),
            ):
                with self.assertRaisesRegex(OSError, "symlink or reparse indirection"):
                    with exclusive_lock(lock):
                        self.fail("reparse lock path must not be acquired")
            self.assertEqual(lock.read_bytes(), b"existing")

    def test_exclusive_lock_rejects_simulated_reparse_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "locks"
            parent.mkdir()
            lock = parent / "operation.lock"
            original_lstat = Path.lstat
            with patch.object(
                Path,
                "lstat",
                _reparse_lstat(original_lstat, {parent}),
            ):
                with self.assertRaisesRegex(OSError, "symlink or reparse indirection"):
                    with exclusive_lock(lock):
                        self.fail("reparse parent must not be traversed")
            self.assertFalse(lock.exists())

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_exclusive_lock_rejects_final_posix_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.lock"
            target.write_bytes(b"target")
            alias = root / "operation.lock"
            alias.symlink_to(target)
            with self.assertRaisesRegex(OSError, "symlink or reparse indirection"):
                with exclusive_lock(alias):
                    self.fail("symlink lock path must not be acquired")
            self.assertEqual(target.read_bytes(), b"target")
            self.assertTrue(alias.is_symlink())

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_exclusive_lock_rejects_intermediate_posix_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            lock = alias / "operation.lock"
            with self.assertRaisesRegex(OSError, "symlink or reparse indirection"):
                with exclusive_lock(lock):
                    self.fail("intermediate symlink must not be traversed")
            self.assertFalse((real / "operation.lock").exists())

    def test_exclusive_lock_rejects_existing_directory_as_lock_file(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / "operation.lock"
            lock.mkdir()
            with self.assertRaisesRegex(OSError, "direct regular file"):
                with exclusive_lock(lock):
                    self.fail("directory must not be acquired as a lock file")


if __name__ == "__main__":
    unittest.main()
