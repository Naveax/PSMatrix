import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_worker as rw
from psmatrix import remote_zip_directory_create_hardening as hardening
from psmatrix import remote_zip_hardening as zip_hardening


class RemoteZipOutputHandleTests(unittest.TestCase):
    def test_install_replaces_windows_output_creator(self):
        self.assertIs(zip_hardening._create_windows_output, hardening._create_windows_output_handle)
        self.assertTrue(getattr(zip_hardening, "_output_handle_identity_hardened", False))

    @unittest.skipUnless(os.name == "nt", "Windows output handle regression")
    def test_live_output_handle_blocks_rename_until_close(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "output.ps1"
            moved = Path(temp) / "moved.ps1"
            fd = hardening._create_windows_output_handle(rw, target)
            try:
                os.write(fd, b"Write-Output 'ok'\n")
                with self.assertRaises(OSError):
                    target.rename(moved)
            finally:
                os.close(fd)
            target.rename(moved)
            self.assertEqual(moved.read_bytes(), b"Write-Output 'ok'\n")

    @unittest.skipUnless(os.name == "nt", "Windows extraction failure regression")
    def test_failed_extraction_does_not_unlink_mutable_output_path(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            destination.mkdir()
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("partial.ps1", b"Write-Output 'partial'\n")

            with patch.object(
                zip_hardening,
                "_copy_member",
                side_effect=rw.WorkerError("forced copy failure"),
            ):
                with self.assertRaises(rw.WorkerError):
                    zip_hardening._secure_extract_zip(rw, payload.getvalue(), destination)

            self.assertTrue((destination / "partial.ps1").exists())


if __name__ == "__main__":
    unittest.main()
