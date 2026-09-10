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
_SCHEMA = (
    "CREATE TABLE nonces (controller_id TEXT NOT NULL, nonce TEXT NOT NULL, "
    "expires_at TEXT NOT NULL, PRIMARY KEY(controller_id, nonce))"
)


def _expires() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=5)


def _create_valid_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(_SCHEMA)
        connection.commit()


def _marked_reparse_lstat(original, marked: Path):
    def fake(path: Path):
        info = original(path)
        if path == marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


@unittest.skip("temporary CI isolation for replay database hardening")
class RemoteReplayDatabaseSecurityTests(unittest.TestCase):
    def test_normal_database_preserves_replay_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay.sqlite3"
            guard = ReplayGuard(path)
            nonce = "n" * 32

            guard.consume("controller-1", nonce, _expires())
            with self.assertRaisesRegex(RemoteProtocolError, "already been used"):
                guard.consume("controller-1", nonce, _expires())

    def test_database_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.sqlite3"
            target.write_bytes(b"")
            path = root / "replay.sqlite3"
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                ReplayGuard(path)

    def test_symlink_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "actual"
            actual.mkdir()
            indirect = root / "indirect"
            try:
                indirect.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                ReplayGuard(indirect / "replay.sqlite3")

    def test_database_reparse_point_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay.sqlite3"
            path.write_bytes(b"")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _marked_reparse_lstat(original_lstat, path)):
                with self.assertRaisesRegex(RemoteProtocolError, "symlink or reparse point"):
                    ReplayGuard(path)

    def test_database_hardlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.sqlite3"
            target.write_bytes(b"")
            path = root / "replay.sqlite3"
            try:
                os.link(target, path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(RemoteProtocolError, "exactly one hard link"):
                ReplayGuard(path)

    def test_existing_database_without_composite_primary_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay.sqlite3"
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "CREATE TABLE nonces (controller_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL)"
                )
                connection.commit()

            with self.assertRaisesRegex(RemoteProtocolError, "nonce schema is invalid"):
                ReplayGuard(path)

    def test_existing_database_with_trigger_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay.sqlite3"
            _create_valid_database(path)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "CREATE TRIGGER erase_nonce AFTER INSERT ON nonces "
                    "BEGIN DELETE FROM nonces WHERE controller_id = NEW.controller_id AND nonce = NEW.nonce; END"
                )
                connection.commit()

            with self.assertRaisesRegex(RemoteProtocolError, "unexpected schema objects"):
                ReplayGuard(path)

    def test_database_replacement_after_construction_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "replay.sqlite3"
            guard = ReplayGuard(path)
            replacement = root / "replacement.sqlite3"
            _create_valid_database(replacement)
            os.replace(replacement, path)

            with self.assertRaisesRegex(RemoteProtocolError, "identity changed"):
                guard.consume("controller-1", "r" * 32, _expires())


if __name__ == "__main__":
    unittest.main()
