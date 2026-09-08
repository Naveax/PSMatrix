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
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class ReplayGuardPathSecurityTests(unittest.TestCase):
    def test_constructor_rejects_intermediate_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink unavailable: {exc}")

            with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                ReplayGuard(alias / "replay.sqlite3")

    def test_constructor_rejects_simulated_reparse_database(self):
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "replay.sqlite3"
            database.touch()
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {database})):
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    ReplayGuard(database)

    def test_consume_revalidates_database_before_sqlite_open(self):
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "replay.sqlite3"
            guard = ReplayGuard(database)
            original_lstat = Path.lstat
            expires = datetime.now(UTC) + timedelta(minutes=5)

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {database})), \
                 patch("psmatrix.remote_protocol.sqlite3.connect") as connect:
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    guard.consume("controller-a", "nonce-value", expires)

            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
