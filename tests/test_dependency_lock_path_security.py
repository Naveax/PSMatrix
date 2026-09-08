import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from unittest.mock import patch

from psmatrix.dependencies import DependencyError, load_dependency_lock


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
                st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _lock_payload() -> str:
    return '{"schema":1,"powershell_modules":[],"native_commands":[]}'


class DependencyLockPathSecurityTests(unittest.TestCase):
    def test_rejects_reparse_lock_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "psmatrix.lock.json"
            path.write_text(_lock_payload(), encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(path)):
                with self.assertRaises(DependencyError):
                    load_dependency_lock(path)

    def test_rejects_intermediate_reparse_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir()
            path = state / "psmatrix.lock.json"
            path.write_text(_lock_payload(), encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(state)):
                with self.assertRaises(DependencyError):
                    load_dependency_lock(path)

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_rejects_final_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text(_lock_payload(), encoding="utf-8")
            alias = root / "psmatrix.lock.json"
            alias.symlink_to(target)
            with self.assertRaises(DependencyError):
                load_dependency_lock(alias)

    def test_direct_lock_preserves_digest_of_parsed_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "psmatrix.lock.json"
            raw = _lock_payload().encode("utf-8")
            path.write_bytes(raw)
            lock = load_dependency_lock(path)
            import hashlib

            self.assertEqual(lock.sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(lock.path, Path(os.path.abspath(os.fspath(path))))


if __name__ == "__main__":
    unittest.main()
