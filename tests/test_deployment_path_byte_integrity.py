import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.deployment as deployment
from psmatrix.deployment import DeploymentError


_REPARSE_POINT = 0x400


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reparse_lstat(target: Path):
    original = Path.lstat
    wanted = _absolute(target)

    def fake(path: Path):
        info = original(path)
        if _absolute(path) == wanted:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=getattr(info, "st_size", 0),
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _worker_source(root: Path) -> Path:
    source = root / "source"
    worker = source / "workers" / "windows"
    worker.mkdir(parents=True)
    package_root = Path(__file__).resolve().parents[1]
    for item in (package_root / "workers" / "windows").iterdir():
        if item.is_file():
            (worker / item.name).write_bytes(item.read_bytes())
    return source


class DeploymentPathByteIntegrityTests(unittest.TestCase):
    def test_source_root_reparse_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            output = root / "worker.zip"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(source)):
                with self.assertRaises(DeploymentError):
                    deployment.build_windows_worker_package(
                        source, output, version="1.0.0"
                    )
            self.assertFalse(output.exists())

    def test_required_worker_reparse_is_rejected_before_packaging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            harness = source / "workers" / "windows" / "worker_harness.ps1"
            output = root / "worker.zip"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(harness)):
                with self.assertRaises(DeploymentError):
                    deployment.build_windows_worker_package(
                        source, output, version="1.0.0"
                    )
            self.assertFalse(output.exists())

    def test_wheel_reparse_is_rejected_before_packaging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            wheel = root / "psmatrix-test.whl"
            wheel.write_bytes(b"wheel")
            output = root / "worker.zip"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(wheel)):
                with self.assertRaises(DeploymentError):
                    deployment.build_windows_worker_package(
                        source, output, version="1.0.0", wheel=wheel
                    )
            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_output_symlink_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            target = root / "target.zip"
            target.write_bytes(b"safe-target")
            output = root / "worker.zip"
            output.symlink_to(target)
            with self.assertRaises(DeploymentError):
                deployment.build_windows_worker_package(
                    source, output, version="1.0.0"
                )
            self.assertEqual(target.read_bytes(), b"safe-target")

    def test_output_reparse_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            output = root / "worker.zip"
            output.write_bytes(b"safe-target")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(output)):
                with self.assertRaises(DeploymentError):
                    deployment.build_windows_worker_package(
                        source, output, version="1.0.0"
                    )
            self.assertEqual(output.read_bytes(), b"safe-target")

    def test_verify_reparse_package_is_rejected_before_zip_parse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            package = root / "worker.zip"
            deployment.build_windows_worker_package(
                source, package, version="1.0.0"
            )
            with patch("pathlib.Path.lstat", new=_reparse_lstat(package)):
                with patch.object(deployment.zipfile, "ZipFile") as zip_file:
                    with self.assertRaises(DeploymentError):
                        deployment.verify_windows_worker_package(package)
                    zip_file.assert_not_called()

    def test_verify_hash_is_bound_to_verified_package_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            package = root / "worker.zip"
            deployment.build_windows_worker_package(
                source, package, version="1.0.0"
            )
            original = package.read_bytes()
            expected_hash = hashlib.sha256(original).hexdigest()
            original_read = deployment._read_direct_file
            package_absolute = _absolute(package)
            reads = {"package": 0}

            def drifting_read(path: Path, *, label: str):
                result = original_read(path, label=label)
                if _absolute(path) == package_absolute:
                    reads["package"] += 1
                    if reads["package"] == 1:
                        package.write_bytes(b"not-a-zip-anymore")
                return result

            with patch.object(
                deployment, "_read_direct_file", side_effect=drifting_read
            ):
                result = deployment.verify_windows_worker_package(package)

            self.assertEqual(reads["package"], 1)
            self.assertTrue(result["valid"])
            self.assertEqual(result["sha256"], expected_hash)

    def test_wheel_manifest_and_archive_use_one_byte_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            wheel = root / "psmatrix-test.whl"
            original = b"original-wheel"
            mutated = b"mutated-wheel-content"
            wheel.write_bytes(original)
            package = root / "worker.zip"
            original_read = deployment._read_direct_file
            wheel_absolute = _absolute(wheel)
            reads = {"wheel": 0}

            def drifting_read(path: Path, *, label: str):
                result = original_read(path, label=label)
                if _absolute(path) == wheel_absolute:
                    reads["wheel"] += 1
                    if reads["wheel"] == 1:
                        wheel.write_bytes(mutated)
                return result

            with patch.object(
                deployment, "_read_direct_file", side_effect=drifting_read
            ):
                deployment.build_windows_worker_package(
                    source, package, version="1.0.0", wheel=wheel
                )

            with zipfile.ZipFile(package) as archive:
                archived = archive.read("python/psmatrix-test.whl")
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            metadata = manifest["files"]["python/psmatrix-test.whl"]
            self.assertEqual(reads["wheel"], 1)
            self.assertEqual(archived, original)
            self.assertEqual(metadata["size"], len(original))
            self.assertEqual(metadata["sha256"], hashlib.sha256(original).hexdigest())

    def test_required_source_file_is_snapshotted_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            harness = source / "workers" / "windows" / "worker_harness.ps1"
            original = harness.read_bytes()
            mutated = original + b"\n# changed after snapshot\n"
            package = root / "worker.zip"
            original_read = deployment._read_direct_file
            harness_absolute = _absolute(harness)
            reads = {"harness": 0}

            def drifting_read(path: Path, *, label: str):
                result = original_read(path, label=label)
                if _absolute(path) == harness_absolute:
                    reads["harness"] += 1
                    if reads["harness"] == 1:
                        harness.write_bytes(mutated)
                return result

            with patch.object(
                deployment, "_read_direct_file", side_effect=drifting_read
            ):
                deployment.build_windows_worker_package(
                    source, package, version="1.0.0"
                )

            with zipfile.ZipFile(package) as archive:
                archived = archive.read("worker/worker_harness.ps1")
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            metadata = manifest["files"]["worker/worker_harness.ps1"]
            self.assertEqual(reads["harness"], 1)
            self.assertEqual(archived, original)
            self.assertEqual(metadata["size"], len(original))
            self.assertEqual(metadata["sha256"], hashlib.sha256(original).hexdigest())

    def test_verify_rejects_archive_symlink_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = _worker_source(root)
            package = root / "worker.zip"
            deployment.build_windows_worker_package(
                source, package, version="1.0.0"
            )
            with zipfile.ZipFile(package, "a") as archive:
                info = zipfile.ZipInfo("worker/link")
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                archive.writestr(info, b"worker_harness.ps1")
            with self.assertRaisesRegex(DeploymentError, "symlink entry"):
                deployment.verify_windows_worker_package(package)


if __name__ == "__main__":
    unittest.main()
