import tempfile
import unittest
from pathlib import Path

from psmatrix.snapshot import diff_snapshots, snapshot_tree


class SnapshotTests(unittest.TestCase):
    def test_created_modified_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            a = root / "a.txt"
            b = root / "b.txt"
            a.write_text("a", encoding="utf-8")
            b.write_text("b", encoding="utf-8")
            before = snapshot_tree(root)
            a.write_text("changed", encoding="utf-8")
            b.unlink()
            (root / "c.txt").write_text("c", encoding="utf-8")
            after = snapshot_tree(root)
            changes = {change.path: change.change for change in diff_snapshots(before, after)}
            self.assertEqual(changes, {"a.txt": "modified", "b.txt": "deleted", "c.txt": "created"})

    def test_excluded_internal_root_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "visible.txt").write_text("visible", encoding="utf-8")
            internal = root / ".psmatrix-internal" / "home"
            internal.mkdir(parents=True)
            (internal / "cache.bin").write_bytes(b"cache")
            snapshot = snapshot_tree(root, excluded_roots={".psmatrix-internal"})
            self.assertEqual(set(snapshot), {"visible.txt"})
