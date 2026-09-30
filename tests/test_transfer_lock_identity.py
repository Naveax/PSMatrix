import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_lock_hardening as hardening


class TransferLockIdentityTests(unittest.TestCase):
    def test_install_wires_transfer_init_and_lock(self):
        self.assertIs(transfer.TransferStore.__init__, hardening._hardened_init)
        self.assertIs(transfer.exclusive_lock, hardening._hardened_exclusive_lock)
        self.assertTrue(
            getattr(
                transfer.TransferStore,
                "_lock_authority_identity_hardened",
                False,
            )
        )

    def test_multiple_stores_reuse_same_registered_lock_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"
            first = transfer.TransferStore(root)
            second = transfer.TransferStore(root)
            self.assertEqual(first.root, second.root)
            scope = hardening._lookup_scope(first.lock_path)
            self.assertIsNotNone(scope)
            assert scope is not None
            self.assertTrue(
                transfer._same_file(scope.root_identity, first._root_identity)
            )
            self.assertTrue(
                transfer._same_file(scope.root_identity, second._root_identity)
            )

    @unittest.skipIf(os.name == "nt", "POSIX root-descriptor lock regression")
    def test_posix_lock_uses_initialized_root_inode(self):
        import fcntl

        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            seen: list[os.stat_result] = []
            real_flock = fcntl.flock

            def record(fd, operation):
                if operation & fcntl.LOCK_EX:
                    seen.append(os.fstat(fd))
                return real_flock(fd, operation)

            with patch.object(fcntl, "flock", side_effect=record):
                with transfer.exclusive_lock(store.lock_path):
                    pass

            self.assertEqual(len(seen), 1)
            self.assertTrue(
                transfer._same_file(seen[0], store._root_identity)
            )

    @unittest.skipIf(os.name == "nt", "POSIX lock pathname replacement regression")
    def test_posix_lock_file_replacement_cannot_split_authority(self):
        import fcntl

        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            store.lock_path.write_text("first", encoding="utf-8")
            first_lock = store.lock_path.lstat()
            store.lock_path.unlink()
            store.lock_path.write_text("replacement", encoding="utf-8")
            replacement_lock = store.lock_path.lstat()
            self.assertFalse(transfer._same_file(first_lock, replacement_lock))

            seen: list[os.stat_result] = []
            real_flock = fcntl.flock

            def record(fd, operation):
                if operation & fcntl.LOCK_EX:
                    seen.append(os.fstat(fd))
                return real_flock(fd, operation)

            with patch.object(fcntl, "flock", side_effect=record):
                with transfer.exclusive_lock(store.lock_path):
                    pass

            self.assertEqual(len(seen), 1)
            self.assertTrue(
                transfer._same_file(seen[0], store._root_identity)
            )
            self.assertEqual(
                store.lock_path.read_text(encoding="utf-8"),
                "replacement",
            )

    @unittest.skipIf(os.name == "nt", "POSIX deterministic root-swap regression")
    def test_posix_root_swap_after_lock_fails_before_yield(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store = transfer.TransferStore(base / "store")
            moved = base / "store-original"
            replacement = base / "store-replacement"
            replacement.mkdir()
            sentinel = replacement / "sentinel.txt"
            sentinel.write_text("replacement", encoding="utf-8")
            yielded = False
            swapped = False

            def swap_root(root, root_fd):
                nonlocal swapped
                if swapped:
                    return
                swapped = True
                root.rename(moved)
                replacement.rename(root)

            with patch.object(
                hardening,
                "_after_posix_lock_acquired",
                side_effect=swap_root,
            ):
                with self.assertRaises(transfer.TransferError):
                    with transfer.exclusive_lock(store.lock_path):
                        yielded = True

            self.assertTrue(swapped)
            self.assertFalse(yielded)
            self.assertEqual(
                (store.root / "sentinel.txt").read_text(encoding="utf-8"),
                "replacement",
            )
            self.assertTrue((moved / "sessions").is_dir())
            self.assertTrue((moved / "objects").is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows live lock pin regression")
    def test_windows_lock_file_cannot_be_renamed_while_held(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            moved = store.root / ".lock-moved"
            with transfer.exclusive_lock(store.lock_path):
                self.assertTrue(store.lock_path.is_file())
                with self.assertRaises(OSError):
                    store.lock_path.rename(moved)
            self.assertTrue(store.lock_path.is_file())
            self.assertFalse(moved.exists())


if __name__ == "__main__":
    unittest.main()
