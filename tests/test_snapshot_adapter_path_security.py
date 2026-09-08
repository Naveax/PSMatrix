import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.snapshot_adapter as snapshot_adapter
from psmatrix.snapshot_adapter import SnapshotAdapter, SnapshotAdapterConfig, SnapshotError


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
                st_size=getattr(info, "st_size", 0),
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _config_payload(cwd: str = ".") -> dict:
    return {
        "schema": 1,
        "adapter_id": "lab-a",
        "provider": "command-test",
        "worker_id": "worker-a",
        "vm_id": "vm-a",
        "snapshot_id": "clean",
        "restore_command": ["python", "restore.py"],
        "measure_command": ["python", "measure.py"],
        "cwd": cwd,
        "expected_after": {},
        "timeout_seconds": 30,
    }


class SnapshotAdapterPathSecurityTests(unittest.TestCase):
    def test_load_rejects_reparse_config_before_json_parse(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "snapshot.json"
            path.write_text(json.dumps(_config_payload()), encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(path)):
                with patch.object(snapshot_adapter.json, "loads", wraps=json.loads) as loads:
                    with self.assertRaises(SnapshotError):
                        SnapshotAdapterConfig.load(path)
                    loads.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_load_rejects_final_symlink_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text(json.dumps(_config_payload()), encoding="utf-8")
            alias = root / "snapshot.json"
            alias.symlink_to(target)
            with self.assertRaises(SnapshotError):
                SnapshotAdapterConfig.load(alias)

    def test_load_rejects_reparse_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd = root / "workspace"
            cwd.mkdir()
            path = root / "snapshot.json"
            path.write_text(json.dumps(_config_payload("workspace")), encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(cwd)):
                with self.assertRaises(SnapshotError):
                    SnapshotAdapterConfig.load(path)

    def test_measure_revalidates_cwd_before_process(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd = Path(temp) / "workspace"
            cwd.mkdir()
            config = SnapshotAdapterConfig(
                adapter_id="lab-a",
                provider="command-test",
                worker_id="worker-a",
                vm_id="vm-a",
                snapshot_id="clean",
                restore_command=("python", "restore.py"),
                measure_command=("python", "measure.py"),
                cwd=cwd,
                timeout_seconds=30,
            )
            config.validate()
            with patch("pathlib.Path.lstat", new=_reparse_lstat(cwd)):
                with patch.object(snapshot_adapter, "_run") as run:
                    with self.assertRaises(SnapshotError):
                        SnapshotAdapter(config).measure("before-pre")
                    run.assert_not_called()

    def test_restore_revalidates_cwd_before_measurement_or_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd = Path(temp) / "workspace"
            cwd.mkdir()
            config = SnapshotAdapterConfig(
                adapter_id="lab-a",
                provider="command-test",
                worker_id="worker-a",
                vm_id="vm-a",
                snapshot_id="clean",
                restore_command=("python", "restore.py"),
                measure_command=("python", "measure.py"),
                cwd=cwd,
                timeout_seconds=30,
            )
            config.validate()
            adapter = SnapshotAdapter(config)
            with patch("pathlib.Path.lstat", new=_reparse_lstat(cwd)):
                with patch.object(adapter, "measure") as measure, patch.object(snapshot_adapter, "_run") as run:
                    with self.assertRaises(SnapshotError):
                        adapter.restore(
                            phase="before",
                            private_key=Path(temp) / "sign.pem",
                            public_key=Path(temp) / "sign.pub",
                        )
                    measure.assert_not_called()
                    run.assert_not_called()

    def test_direct_config_preserves_direct_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd = root / "workspace"
            cwd.mkdir()
            path = root / "snapshot.json"
            path.write_text(json.dumps(_config_payload("workspace")), encoding="utf-8")
            config = SnapshotAdapterConfig.load(path)
            self.assertEqual(config.cwd, Path(os.path.abspath(os.fspath(cwd))))


if __name__ == "__main__":
    unittest.main()
