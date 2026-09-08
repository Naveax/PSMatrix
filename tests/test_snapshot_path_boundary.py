import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.snapshot import snapshot_tree


_REPARSE_POINT = 0x400


def _reparse_lstat(*targets: Path):
    original = Path.lstat
    wanted = {Path(os.path.abspath(os.fspath(item))) for item in targets}

    def fake(path: Path):
        info = original(path)
        current = Path(os.path.abspath(os.fspath(path)))
        if current in wanted:
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


class SnapshotPathBoundaryTests(unittest.TestCase):
    def test_reparse_file_is_recorded_without_hashing_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            alias = root / "alias.txt"
            alias.write_text("sensitive", encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(alias)):
                snapshot = snapshot_tree(root)
            self.assertEqual(snapshot["alias.txt"]["kind"], "indirect")
            self.assertNotIn("sha256", snapshot["alias.txt"])

    def test_symlink_file_is_recorded_without_hashing_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.txt"
            alias = root / "alias.txt"
            target.write_text("target", encoding="utf-8")
            try:
                alias.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"Symlink creation is unavailable: {exc}")
            snapshot = snapshot_tree(root)
            self.assertEqual(snapshot["alias.txt"]["kind"], "indirect")
            self.assertNotIn("sha256", snapshot["alias.txt"])
            self.assertIn("sha256", snapshot["target.txt"])

    def test_reparse_directory_is_not_traversed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            redirect = root / "redirect"
            redirect.mkdir()
            (redirect / "secret.txt").write_text("secret", encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(redirect)):
                snapshot = snapshot_tree(root)
            self.assertEqual(snapshot["redirect"]["kind"], "indirect")
            self.assertNotIn("redirect/secret.txt", snapshot)

    def test_special_file_metadata_does_not_require_content_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = root / "special.bin"
            item.write_bytes(b"fixture")
            original = Path.lstat

            def special_lstat(path: Path):
                info = original(path)
                if Path(os.path.abspath(os.fspath(path))) == item:
                    return SimpleNamespace(
                        st_mode=0,
                        st_size=info.st_size,
                        st_mtime_ns=info.st_mtime_ns,
                        st_dev=info.st_dev,
                        st_ino=info.st_ino,
                        st_file_attributes=0,
                    )
                return info

            with patch("pathlib.Path.lstat", new=special_lstat):
                snapshot = snapshot_tree(root)
            self.assertEqual(snapshot["special.bin"]["kind"], "special")
            self.assertNotIn("sha256", snapshot["special.bin"])


if __name__ == "__main__":
    unittest.main()
