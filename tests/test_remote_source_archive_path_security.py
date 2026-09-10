import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.remote_worker as remote_worker
from psmatrix.remote_worker import WorkerError, create_source_archive


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class _OpenSwapProxy:
    def __init__(self, delegate, source: Path, replacement: Path):
        self._delegate = delegate
        self._source = source
        self._replacement = replacement
        self.swapped = False

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def open(self, path, flags, *args, **kwargs):
        candidate = Path(path)
        if candidate == self._source and not self.swapped:
            self._source.unlink()
            self._replacement.replace(self._source)
            self.swapped = True
        return self._delegate.open(path, flags, *args, **kwargs)


class RemoteSourceArchivePathSecurityTests(unittest.TestCase):
    def test_archive_reads_direct_single_link_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "entry.ps1"
            source.write_text("'ok'\n", encoding="utf-8")

            payload = create_source_archive(root, [source])

            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                self.assertEqual(archive.namelist(), ["entry.ps1"])
                self.assertEqual(archive.read("entry.ps1"), b"'ok'\n")

    def test_archive_rejects_reparse_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "entry.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {source})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    create_source_archive(root, [source])

    def test_archive_rejects_reparse_source_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "entry.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {root})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    create_source_archive(root, [source])

    def test_archive_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
            source = outside / "entry.ps1"
            source.write_text("'outside'\n", encoding="utf-8")
            self.addCleanup(lambda: source.unlink(missing_ok=True))
            linked = root / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                create_source_archive(root, [linked / "entry.ps1"])

    def test_archive_rejects_hardlinked_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.ps1"
            outside.write_text("'outside'\n", encoding="utf-8")
            source = root / "entry.ps1"
            try:
                os.link(outside, source)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(WorkerError, "exactly one hard link"):
                create_source_archive(root, [source])

    def test_archive_rejects_file_replacement_between_lstat_and_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "entry.ps1"
            source.write_text("'original'\n", encoding="utf-8")
            replacement = root / "replacement.ps1"
            replacement.write_text("'replacement'\n", encoding="utf-8")
            proxy = _OpenSwapProxy(os, source, replacement)

            with patch.object(remote_worker, "os", proxy):
                with self.assertRaises(WorkerError):
                    create_source_archive(root, [source])
            self.assertTrue(proxy.swapped, "source replacement must occur before fail-closed rejection")

    def test_archive_rejects_lexically_outside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / f"{root.name}-outside.ps1"
            outside.write_text("'outside'\n", encoding="utf-8")
            self.addCleanup(lambda: outside.unlink(missing_ok=True))

            with self.assertRaisesRegex(WorkerError, "escapes project root"):
                create_source_archive(root, [outside])


if __name__ == "__main__":
    unittest.main()
