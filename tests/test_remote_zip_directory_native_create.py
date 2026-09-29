import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_worker as rw
from psmatrix import remote_workspace_create_hardening as workspace_hardening
from psmatrix import remote_zip_directory_create_hardening as hardening
from psmatrix import remote_zip_hardening as zip_hardening


class RemoteZipDirectoryNativeCreateTests(unittest.TestCase):
    def test_install_replaces_only_windows_extractor(self):
        self.assertIs(zip_hardening._extract_windows, hardening._hardened_extract_windows)
        self.assertTrue(
            getattr(zip_hardening, "_nested_directory_native_create_hardened", False)
        )

    @unittest.skipUnless(os.name == "nt", "Windows native directory create regression")
    def test_nested_directories_use_native_create_handles(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            destination.mkdir()
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("a/b/script.ps1", b"Write-Output 'ok'\n")

            created = []
            original = workspace_hardening._create_windows_directory_handle

            def recording_create(worker, path):
                created.append(Path(path))
                return original(worker, path)

            with patch.object(
                workspace_hardening,
                "_create_windows_directory_handle",
                side_effect=recording_create,
            ):
                zip_hardening._secure_extract_zip(rw, payload.getvalue(), destination)

            self.assertEqual(created, [destination / "a", destination / "a" / "b"])
            self.assertEqual(
                (destination / "a" / "b" / "script.ps1").read_bytes(),
                b"Write-Output 'ok'\n",
            )

    @unittest.skipUnless(os.name == "nt", "Windows native directory create regression")
    def test_existing_direct_parent_is_reused_and_child_is_native_created(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            existing = destination / "a"
            existing.mkdir(parents=True)
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("a/b/data.txt", b"data")

            created = []
            original = workspace_hardening._create_windows_directory_handle

            def recording_create(worker, path):
                created.append(Path(path))
                return original(worker, path)

            with patch.object(
                workspace_hardening,
                "_create_windows_directory_handle",
                side_effect=recording_create,
            ):
                zip_hardening._secure_extract_zip(rw, payload.getvalue(), destination)

            self.assertEqual(created, [existing / "b"])
            self.assertEqual((existing / "b" / "data.txt").read_bytes(), b"data")


if __name__ == "__main__":
    unittest.main()
