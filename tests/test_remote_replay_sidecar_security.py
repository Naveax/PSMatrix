import os
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_protocol import ReplayGuard, RemoteProtocolError


_REPARSE_POINT = 0x400


def _expires() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=5)


def _marked_reparse_lstat(original, marked: Path):
    def fake(path: Path):
        info = original(path)
        if Path(path) == marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class RemoteReplaySidecarSecurityTests(unittest.TestCase):
    def test_reparse_sidecar_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            sidecar = Path(str(guard.path) + "-journal")
            sidecar.write_bytes(b"")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _marked_reparse_lstat(original_lstat, sidecar)), patch(
                "psmatrix.remote_protocol.sqlite3.connect"
            ) as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "SQLite sidecar"):
                    guard.consume("controller-1", "r" * 32, _expires())
            connect.assert_not_called()

    def test_symlink_sidecar_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guard = ReplayGuard(root / "replay.sqlite3")
            target = root / "sidecar-target"
            target.write_bytes(b"target")
            sidecar = Path(str(guard.path) + "-journal")
            try:
                sidecar.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    guard.consume("controller-1", "s" * 32, _expires())
            connect.assert_not_called()

    def test_hardlinked_sidecar_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guard = ReplayGuard(root / "replay.sqlite3")
            peer = root / "sidecar-peer"
            peer.write_bytes(b"peer")
            sidecar = Path(str(guard.path) + "-journal")
            try:
                os.link(peer, sidecar)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "exactly one hard link"):
                    guard.consume("controller-1", "h" * 32, _expires())
            connect.assert_not_called()
            self.assertEqual(peer.read_bytes(), b"peer")

    def test_sidecar_created_during_connect_is_revalidated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guard = ReplayGuard(root / "replay.sqlite3")
            peer = root / "sidecar-peer"
            peer.write_bytes(b"peer")
            sidecar = Path(str(guard.path) + "-journal")
            probe = root / "hardlink-probe"
            try:
                os.link(peer, probe)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            probe.unlink()
            original_connect = sqlite3.connect

            def connect_and_inject(*args, **kwargs):
                connection = original_connect(*args, **kwargs)
                os.link(peer, sidecar)
                return connection

            with patch("psmatrix.remote_protocol.sqlite3.connect", side_effect=connect_and_inject):
                with self.assertRaisesRegex(RemoteProtocolError, "exactly one hard link"):
                    guard.consume("controller-1", "c" * 32, _expires())
            self.assertEqual(peer.read_bytes(), b"peer")


if __name__ == "__main__":
    unittest.main()
