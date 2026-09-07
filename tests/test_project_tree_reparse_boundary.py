import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.cache import execution_context_evidence
from psmatrix.runner import ScriptRunner


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class ProjectTreeReparseBoundaryTests(unittest.TestCase):
    def _project(self, root: Path):
        source = root / "main.ps1"
        source.write_text("'main'", encoding="utf-8")
        reparse_dir = root / "junction-like"
        reparse_dir.mkdir()
        (reparse_dir / "outside.ps1").write_text("'outside'", encoding="utf-8")
        reparse_file = root / "reparse-like.ps1"
        reparse_file.write_text("'indirect'", encoding="utf-8")
        ordinary = root / "ordinary.ps1"
        ordinary.write_text("'ordinary'", encoding="utf-8")
        return source, reparse_dir, reparse_file, ordinary

    def test_execution_context_excludes_windows_reparse_directory_and_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, reparse_dir, reparse_file, ordinary = self._project(root)
            original_lstat = Path.lstat
            marked = {reparse_dir, reparse_file}
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, marked)):
                evidence = execution_context_evidence(source)

            paths = {str(item.get("relative_path")) for item in evidence["entries"]}
            self.assertIn("main.ps1", paths)
            self.assertIn("ordinary.ps1", paths)
            self.assertNotIn("junction-like", paths)
            self.assertNotIn("junction-like/outside.ps1", paths)
            self.assertNotIn("reparse-like.ps1", paths)

    def test_workspace_copy_excludes_windows_reparse_directory_and_file(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as output:
            root = Path(temp)
            workspace = Path(output)
            _, reparse_dir, reparse_file, ordinary = self._project(root)
            original_lstat = Path.lstat
            marked = {reparse_dir, reparse_file}
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, marked)):
                ScriptRunner._copy_project(root, workspace)

            self.assertTrue((workspace / "main.ps1").is_file())
            self.assertTrue((workspace / ordinary.name).is_file())
            self.assertFalse((workspace / reparse_dir.name).exists())
            self.assertFalse((workspace / reparse_file.name).exists())


if __name__ == "__main__":
    unittest.main()
