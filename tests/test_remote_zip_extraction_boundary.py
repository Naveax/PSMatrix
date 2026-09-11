import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_zip_hardening
from psmatrix.remote_worker import WorkerError, _safe_extract_zip


def _artifact(entries: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return buffer.getvalue()


class RemoteZipExtractionBoundaryTests(unittest.TestCase):
    def test_normal_nested_extraction_succeeds(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            destination.mkdir()
            _safe_extract_zip(
                _artifact({"entry.ps1": "'ok'", "nested/data.txt": "payload"}),
                destination,
            )
            self.assertEqual((destination / "entry.ps1").read_text(encoding="utf-8"), "'ok'")
            self.assertEqual((destination / "nested" / "data.txt").read_text(encoding="utf-8"), "payload")

    def test_missing_destination_is_rejected_without_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            with self.assertRaisesRegex(WorkerError, "destination is unavailable"):
                _safe_extract_zip(_artifact({"entry.ps1": "'ok'"}), destination)
            self.assertFalse(destination.exists())

    @unittest.skipIf(os.name == "nt", "POSIX final-entry replacement regression")
    def test_output_replacement_after_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            destination.mkdir()
            target = destination / "entry.ps1"
            original_copy = remote_zip_hardening._copy_member
            swapped = False

            def replace_output(rw, source, output, *, info):
                nonlocal swapped
                original_copy(rw, source, output, info=info)
                target.unlink()
                target.write_text("replacement", encoding="utf-8")
                swapped = True

            with patch("psmatrix.remote_zip_hardening._copy_member", side_effect=replace_output):
                with self.assertRaisesRegex(WorkerError, "output identity changed"):
                    _safe_extract_zip(_artifact({"entry.ps1": "payload"}), destination)
            self.assertTrue(swapped)
            self.assertFalse(target.exists())

    def test_preexisting_symlink_parent_is_rejected_without_outside_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "workspace"
            destination.mkdir()
            outside = root / "outside"
            outside.mkdir()
            nested = destination / "nested"
            try:
                nested.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlink creation is unavailable: {exc}")
            with self.assertRaises(WorkerError):
                _safe_extract_zip(_artifact({"nested/payload.txt": "secret"}), destination)
            self.assertFalse((outside / "payload.txt").exists())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative race regression")
    def test_parent_replacement_after_pin_is_rejected_without_redirected_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "workspace"
            destination.mkdir()
            outside = root / "outside"
            outside.mkdir()
            original_create = remote_zip_hardening._create_posix_output
            swapped = False

            def replace_parent(rw, parent_fd, name, path):
                nonlocal swapped
                if not swapped:
                    parent = destination / "nested"
                    moved = destination / "nested-original"
                    parent.rename(moved)
                    try:
                        parent.symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest(f"directory symlink creation is unavailable: {exc}")
                    swapped = True
                return original_create(rw, parent_fd, name, path)

            with patch("psmatrix.remote_zip_hardening._create_posix_output", side_effect=replace_parent):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point|identity changed"):
                    _safe_extract_zip(_artifact({"nested/payload.txt": "secret"}), destination)
            self.assertTrue(swapped)
            self.assertFalse((outside / "payload.txt").exists())
            self.assertFalse((destination / "nested-original" / "payload.txt").exists())

    def test_existing_destination_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "workspace"
            destination.mkdir()
            target = destination / "entry.ps1"
            target.write_text("trusted", encoding="utf-8")
            with self.assertRaises(WorkerError):
                _safe_extract_zip(_artifact({"entry.ps1": "attacker"}), destination)
            self.assertEqual(target.read_text(encoding="utf-8"), "trusted")


if __name__ == "__main__":
    unittest.main()
