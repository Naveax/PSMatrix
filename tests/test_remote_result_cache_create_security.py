import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_result_cache_create_hardening as hardening
from psmatrix import remote_worker as rw


class RemoteResultCacheCreateHardeningTests(unittest.TestCase):
    def test_install_replaces_worker_service_initializer(self):
        self.assertIs(rw.WorkerService.__init__, hardening._hardened_service_init)
        self.assertTrue(
            getattr(rw.WorkerService, "_result_cache_creation_identity_hardened", False)
        )

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_posix_result_cache_create_returns_visible_pinned_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path, identity = hardening._create_posix_result_cache(rw, root)
            self.assertEqual(path, root / ".job-results")
            self.assertTrue(path.is_dir())
            rw._assert_direct_directory_identity(path, identity, label="Worker result cache")

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_posix_existing_result_cache_is_reused_by_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = root / ".job-results"
            expected.mkdir()
            before = rw._filesystem_identity(expected.lstat())
            path, identity = hardening._create_posix_result_cache(rw, root)
            self.assertEqual(path, expected)
            self.assertEqual(identity, before)

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_root_swap_during_create_cannot_redirect_result_cache(self):
        if os.mkdir not in getattr(os, "supports_dir_fd", set()):
            self.skipTest("dir_fd mkdir unavailable")
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent / "workspace"
            root.mkdir()
            original = parent / "workspace.original"
            real_mkdir = os.mkdir
            swapped = {"done": False}

            def swapping_mkdir(path, mode=0o777, *, dir_fd=None):
                if dir_fd is not None and path == ".job-results" and not swapped["done"]:
                    swapped["done"] = True
                    root.rename(original)
                    real_mkdir(root)
                return real_mkdir(path, mode, dir_fd=dir_fd)

            with patch.object(hardening.os, "mkdir", side_effect=swapping_mkdir):
                with self.assertRaises(rw.WorkerError):
                    hardening._create_posix_result_cache(rw, root)

            self.assertTrue(swapped["done"])
            self.assertFalse((root / ".job-results").exists())
            self.assertFalse((original / ".job-results").exists())

    @unittest.skipUnless(os.name == "nt", "Windows result-cache regression")
    def test_windows_result_cache_handle_identity_is_stable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path, identity = hardening._create_windows_result_cache(rw, root)
            self.assertTrue(path.is_dir())
            rw._assert_direct_directory_identity(path, identity, label="Worker result cache")

    @unittest.skipUnless(os.name == "nt", "Windows result-cache concurrency regression")
    def test_windows_result_cache_reopens_concurrent_creator(self):
        from psmatrix import remote_workspace_create_hardening as workspace_hardening

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = root / ".job-results"

            def concurrent_winner(worker, path):
                self.assertEqual(path, expected)
                path.mkdir()
                raise rw.WorkerError(
                    f"Unable to atomically create worker job workspace {path}: WinError 183"
                )

            with patch.object(
                workspace_hardening,
                "_create_windows_directory_handle",
                side_effect=concurrent_winner,
            ):
                path, identity = hardening._create_windows_result_cache(rw, root)

            self.assertEqual(path, expected)
            self.assertTrue(path.is_dir())
            rw._assert_direct_directory_identity(path, identity, label="Worker result cache")


if __name__ == "__main__":
    unittest.main()
