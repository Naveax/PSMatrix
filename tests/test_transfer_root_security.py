import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_root_hardening as hardening


class TransferRootHardeningTests(unittest.TestCase):
    def test_install_preserves_root_bootstrap_beneath_lock_wrapper(self):
        from psmatrix import transfer_lock_hardening as lock_hardening

        self.assertIs(transfer.TransferStore.__init__, lock_hardening._hardened_init)
        self.assertIs(lock_hardening._ORIGINAL_INIT, hardening._hardened_init)
        self.assertTrue(
            getattr(transfer.TransferStore, "_root_bootstrap_identity_hardened", False)
        )
        self.assertTrue(
            getattr(transfer.TransferStore, "_lock_authority_identity_hardened", False)
        )

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_posix_bootstrap_preserves_recursive_create_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "a" / "b" / "store"
            store = transfer.TransferStore(root)
            self.assertEqual(store.root, root.resolve())
            self.assertTrue(store.sessions.is_dir())
            self.assertTrue(store.objects.is_dir())
            store._validate_roots()

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_existing_store_tree_is_reused_with_same_identities(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"
            (root / "sessions").mkdir(parents=True)
            (root / "objects").mkdir()
            root_before = root.lstat()
            sessions_before = (root / "sessions").lstat()
            objects_before = (root / "objects").lstat()
            store = transfer.TransferStore(root)
            self.assertTrue(transfer._same_file(store._root_identity, root_before))
            self.assertTrue(transfer._same_file(store._sessions_identity, sessions_before))
            self.assertTrue(transfer._same_file(store._objects_identity, objects_before))

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_parent_swap_during_root_create_does_not_redirect_store(self):
        if os.mkdir not in getattr(os, "supports_dir_fd", set()):
            self.skipTest("dir_fd mkdir unavailable")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            holder = base / "holder"
            holder.mkdir()
            original = base / "holder.original"
            target = holder / "store"
            real_mkdir = os.mkdir
            swapped = {"done": False}

            def swapping_mkdir(path, mode=0o777, *, dir_fd=None):
                if dir_fd is not None and path == "store" and not swapped["done"]:
                    swapped["done"] = True
                    holder.rename(original)
                    real_mkdir(holder)
                return real_mkdir(path, mode, dir_fd=dir_fd)

            with patch.object(hardening.os, "mkdir", side_effect=swapping_mkdir):
                with self.assertRaises(transfer.TransferError):
                    transfer.TransferStore(target)

            self.assertTrue(swapped["done"])
            self.assertFalse((holder / "store").exists())
            self.assertTrue((original / "store").is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows transfer bootstrap regression")
    def test_windows_bootstrap_returns_direct_store_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "nested" / "store"
            store = transfer.TransferStore(root)
            store._validate_roots()
            self.assertTrue(store.root.is_dir())
            self.assertTrue(store.sessions.is_dir())
            self.assertTrue(store.objects.is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows transfer bootstrap concurrency regression")
    def test_windows_bootstrap_reopens_concurrent_creator(self):
        from psmatrix import remote_workspace_create_hardening as workspace_hardening

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "store"

            def concurrent_winner(worker, path):
                path.mkdir()
                raise transfer.TransferError(
                    f"Unable to atomically create worker job workspace {path}: WinError 183"
                )

            with patch.object(
                workspace_hardening,
                "_create_windows_directory_handle",
                side_effect=concurrent_winner,
            ):
                store = transfer.TransferStore(root)

            store._validate_roots()
            self.assertEqual(store.root, root.resolve())
            self.assertTrue(store.sessions.is_dir())
            self.assertTrue(store.objects.is_dir())


if __name__ == "__main__":
    unittest.main()
