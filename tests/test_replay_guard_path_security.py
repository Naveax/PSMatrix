import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_protocol import ReplayGuard, RemoteProtocolError


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if Path(path) in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _expires() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=5)


class ReplayGuardPathSecurityTests(unittest.TestCase):
    def test_rejects_intermediate_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink unavailable: {exc}")

            with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                ReplayGuard(alias / "replay.sqlite3")

    def test_rejects_simulated_reparse_database_at_construction(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay.sqlite3"
            path.write_bytes(b"")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {path})):
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    ReplayGuard(path)

    def test_consume_revalidates_database_before_sqlite_use(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {guard.path})), \
                 patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()

    def test_consume_revalidates_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            guard = ReplayGuard(state / "replay.sqlite3")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {state})), \
                 patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()

    def test_consume_revalidates_sqlite_sidecars_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            sidecar = Path(str(guard.path) + "-journal")
            sidecar.write_bytes(b"")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {sidecar})), \
                 patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()

    def test_consume_rejects_hardlinked_database_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            peer = Path(temp) / "database-peer.sqlite3"
            try:
                os.link(guard.path, peer)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "direct regular file with one link"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()
            self.assertTrue(peer.is_file())

    def test_consume_rejects_hardlinked_sqlite_sidecar_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            peer = Path(temp) / "sidecar-peer.bin"
            peer.write_bytes(b"peer")
            sidecar = Path(str(guard.path) + "-journal")
            try:
                os.link(peer, sidecar)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "direct regular file with one link"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()
            self.assertEqual(peer.read_bytes(), b"peer")

    def test_consume_rejects_direct_parent_replacement_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            state = base / "state"
            guard = ReplayGuard(state / "replay.sqlite3")
            original_state = base / "state-original"
            state.replace(original_state)
            state.mkdir()

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "parent changed after initialization"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()
            self.assertTrue((original_state / "replay.sqlite3").is_file())

    def test_consume_rejects_direct_database_replacement_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            guard = ReplayGuard(Path(temp) / "replay.sqlite3")
            original = Path(temp) / "replay-original.sqlite3"
            guard.path.replace(original)
            guard.path.write_bytes(original.read_bytes())

            with patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "database changed after initialization"):
                    guard.consume("controller-a", "n" * 32, _expires())
            connect.assert_not_called()
            self.assertTrue(original.is_file())


if __name__ == "__main__":
    unittest.main()
