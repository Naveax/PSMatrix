import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_worker as rw
from psmatrix import remote_workspace_create_hardening as hardening


class RemoteWorkspaceCreateIdentityTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_create_workspace_returns_pinned_direct_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            job_id = str(uuid.uuid4())
            pin = hardening._create_posix_workspace(rw, root, job_id)
            try:
                self.assertEqual(pin.path, root / job_id)
                self.assertTrue(pin.path.is_dir())
                self.assertEqual(len(pin.posix_fds), 2)
            finally:
                pin.close()

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_existing_workspace_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            job_id = str(uuid.uuid4())
            (root / job_id).mkdir()
            with self.assertRaisesRegex(rw.WorkerError, "already exists"):
                hardening._create_posix_workspace(rw, root, job_id)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_root_replacement_during_creation_does_not_redirect_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspaces"
            root.mkdir()
            moved = base / "workspaces-original"
            replacement = root
            job_id = str(uuid.uuid4())
            real_mkdir = os.mkdir
            swapped = False

            def swap_then_mkdir(path, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if not swapped and path == job_id and dir_fd is not None:
                    swapped = True
                    root.rename(moved)
                    replacement.mkdir()
                return real_mkdir(path, mode, dir_fd=dir_fd)

            with patch.object(hardening.os, "mkdir", side_effect=swap_then_mkdir):
                with self.assertRaisesRegex(rw.WorkerError, "identity changed"):
                    hardening._create_posix_workspace(rw, root, job_id)

            self.assertFalse((replacement / job_id).exists())
            self.assertTrue((moved / job_id).is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows native create-and-pin regression")
    def test_windows_workspace_cannot_be_renamed_while_pin_is_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            job_id = str(uuid.uuid4())
            pin = hardening._create_windows_workspace(rw, root, job_id)
            try:
                with self.assertRaises(OSError):
                    pin.path.rename(root / f"{job_id}.moved")
            finally:
                pin.close()

    def test_install_marks_workspace_creation_hardening(self):
        self.assertTrue(getattr(rw.WindowsJobExecutor, "_workspace_creation_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
