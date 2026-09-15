import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import gate
from psmatrix.gate import GateError
from psmatrix import gate_key_hardening as hardening


class GateKeyIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(gate, "_key_identity_hardened", False))
        self.assertEqual(gate._load_key.__module__, "psmatrix.gate_key_hardening")

    def test_create_persists_and_reuses_same_key(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            first = gate._load_key(home, create=True)
            second = gate._load_key(home, create=True)
            self.assertEqual(len(first), 32)
            self.assertEqual(first, second)
            if os.name != "nt":
                mode = stat.S_IMODE((home / "gate" / "hmac.key").lstat().st_mode)
                self.assertEqual(mode, 0o600)

    def test_create_false_rejects_missing_key(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(GateError):
                gate._load_key(Path(temp) / "home", create=False)

    @unittest.skipUnless(os.name == "posix", "POSIX key metadata coverage")
    def test_symlink_directory_fifo_and_device_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            gate_dir = home / "gate"
            gate_dir.mkdir(parents=True)
            path = gate_dir / "hmac.key"

            target = Path(temp) / "target.key"
            target.write_bytes(b"x" * 32)
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaises(GateError):
                gate._load_key(home, create=True)
            path.unlink()

            path.mkdir()
            with self.assertRaises(GateError):
                gate._load_key(home, create=True)
            path.rmdir()

            os.mkfifo(path, 0o600)
            with self.assertRaises(GateError):
                gate._load_key(home, create=True)
            path.unlink()

            null_info = Path(os.devnull).stat()
            with self.assertRaises(GateError):
                hardening._validate_key_info(gate, null_info)

    @unittest.skipUnless(os.name == "posix", "POSIX permission coverage")
    def test_existing_key_with_broad_permissions_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = home / "gate" / "hmac.key"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"a" * 32)
            path.chmod(0o644)
            with self.assertRaises(GateError):
                gate._load_key(home, create=True)
            self.assertEqual(path.read_bytes(), b"a" * 32)

    @unittest.skipUnless(os.name == "posix", "POSIX hardlink coverage")
    def test_hardlinked_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = home / "gate" / "hmac.key"
            path.parent.mkdir(parents=True)
            outside = Path(temp) / "outside.key"
            outside.write_bytes(b"a" * 32)
            outside.chmod(0o600)
            try:
                os.link(outside, path)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(GateError):
                gate._load_key(home, create=False)

    @unittest.skipUnless(os.name == "posix", "POSIX replacement-race coverage")
    def test_identity_swap_between_lstat_and_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = home / "gate" / "hmac.key"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"a" * 32)
            path.chmod(0o600)
            moved = path.with_name("hmac.old")

            def replace(candidate: Path) -> None:
                if candidate == path and not moved.exists():
                    candidate.rename(moved)
                    candidate.write_bytes(b"b" * 32)
                    candidate.chmod(0o600)

            with mock.patch.object(hardening, "_after_key_lstat", side_effect=replace):
                with self.assertRaises(GateError):
                    gate._load_key(home, create=False)

    @unittest.skipUnless(os.name == "posix", "POSIX write-loop coverage")
    def test_partial_writes_are_completed_and_fsynced(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            original_write = os.write
            original_fsync = os.fsync
            write_sizes: list[int] = []
            fsync_calls: list[int] = []

            def short_write(fd: int, data) -> int:
                limited = data[:5]
                written = original_write(fd, limited)
                write_sizes.append(written)
                return written

            def tracked_fsync(fd: int) -> None:
                fsync_calls.append(fd)
                original_fsync(fd)

            with mock.patch.object(hardening.os, "write", side_effect=short_write), mock.patch.object(
                hardening.os, "fsync", side_effect=tracked_fsync
            ):
                key = gate._load_key(home, create=True)

            self.assertEqual(len(key), 32)
            self.assertGreater(len(write_sizes), 1)
            self.assertTrue(fsync_calls)
            self.assertEqual((home / "gate" / "hmac.key").read_bytes(), key)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow coverage")
    def test_key_open_uses_no_follow_when_available(self):
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            self.skipTest("O_NOFOLLOW unavailable")
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            gate._load_key(home, create=True)
            original_open = os.open
            key_flags: list[int] = []

            def tracked_open(path, flags, *args, **kwargs):
                if str(path) == "hmac.key":
                    key_flags.append(flags)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(hardening.os, "open", side_effect=tracked_open):
                gate._load_key(home, create=False)
            self.assertTrue(key_flags)
            self.assertTrue(all(flags & nofollow for flags in key_flags))

    @unittest.skipUnless(os.name == "posix", "POSIX create-race coverage")
    def test_concurrent_initializer_reads_winner_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = home / "gate" / "hmac.key"
            winner = b"w" * 32

            def lose_race(*args, **kwargs):
                path.write_bytes(winner)
                path.chmod(0o600)
                raise FileExistsError(path)

            with mock.patch.object(hardening.os, "link", side_effect=lose_race):
                loaded = gate._load_key(home, create=True)

            self.assertEqual(loaded, winner)
            self.assertEqual(path.read_bytes(), winner)

    @unittest.skipUnless(os.name == "nt", "Windows O_BINARY coverage")
    def test_windows_creation_uses_binary_mode(self):
        binary = getattr(os, "O_BINARY", 0)
        if not binary:
            self.skipTest("O_BINARY unavailable")
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            original_open = os.open
            create_flags: list[int] = []

            def tracked_open(path, flags, *args, **kwargs):
                if str(path).endswith(".tmp"):
                    create_flags.append(flags)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(hardening.os, "open", side_effect=tracked_open):
                gate._load_key(home, create=True)
            self.assertTrue(create_flags)
            self.assertTrue(all(flags & binary for flags in create_flags))


if __name__ == "__main__":
    unittest.main()
