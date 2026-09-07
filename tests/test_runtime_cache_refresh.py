import hashlib
import io
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.models import RuntimeSpec
from psmatrix.runtime import RuntimeManager


class RuntimeCacheRefreshTests(unittest.TestCase):
    def test_invalid_cached_archive_is_replaced_in_same_install_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")

            good_archive = root / "verified-runtime.tar.gz"
            script = b'#!/bin/sh\necho 7.6.4\n'
            with tarfile.open(good_archive, "w:gz") as tar:
                info = tarfile.TarInfo("pwsh")
                info.mode = 0o755
                info.size = len(script)
                tar.addfile(info, io.BytesIO(script))
            expected_hash = hashlib.sha256(good_archive.read_bytes()).hexdigest()

            cached_archive = manager.cache_dir / spec.artifact_name
            cached_archive.write_bytes(b"corrupt stale cache")

            download_calls = []

            def replace_cache(url: str, destination: Path, overwrite: bool = False) -> None:
                download_calls.append((url, destination, overwrite))
                self.assertEqual(destination, cached_archive)
                self.assertTrue(overwrite)
                shutil.copyfile(good_archive, destination)

            with (
                patch.object(manager, "_fetch_expected_hash", return_value=expected_hash),
                patch.object(manager, "_download", side_effect=replace_cache),
                patch.object(manager, "_probe_executable", return_value=spec.version),
            ):
                installation = manager.install(spec)

            self.assertTrue(installation.executable.is_file())
            self.assertEqual(installation.sha256, expected_hash)
            self.assertEqual(len(download_calls), 1)
            self.assertEqual(
                hashlib.sha256(cached_archive.read_bytes()).hexdigest(), expected_hash
            )


if __name__ == "__main__":
    unittest.main()
