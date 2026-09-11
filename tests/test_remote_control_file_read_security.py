import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.remote_worker import (
    RemoteEndpoint,
    WorkerConfig,
    WorkerError,
    _pin_direct_directory,
    _read_pinned_json,
    certificate_sha256,
)


class RemoteControlFileReadSecurityTests(unittest.TestCase):
    def _replacement_open(self, target: Path, replacement: Path):
        original_open = os.open
        target_key = os.path.normcase(os.path.abspath(os.fspath(target)))
        swapped = False

        def swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            candidate_key = os.path.normcase(os.path.abspath(os.fspath(path)))
            if candidate_key == target_key and not swapped:
                target.unlink()
                replacement.replace(target)
                swapped = True
            return original_open(path, flags, *args, **kwargs)

        def did_swap() -> bool:
            return swapped

        return swapping_open, did_swap

    def test_worker_config_replacement_between_lstat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "worker.json"
            target.write_text('{"schema":1}', encoding="utf-8")
            replacement = root / "replacement.json"
            replacement.write_text('{"schema":1}', encoding="utf-8")
            swapping_open, did_swap = self._replacement_open(target, replacement)

            with patch("psmatrix.remote_worker.os.open", side_effect=swapping_open):
                with self.assertRaisesRegex(WorkerError, "identity changed while opening"):
                    WorkerConfig.load(target)

            self.assertTrue(did_swap())

    def test_endpoint_config_replacement_between_lstat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "endpoint.json"
            target.write_text('{"schema":1}', encoding="utf-8")
            replacement = root / "replacement.json"
            replacement.write_text('{"schema":1}', encoding="utf-8")
            swapping_open, did_swap = self._replacement_open(target, replacement)

            with patch("psmatrix.remote_worker.os.open", side_effect=swapping_open):
                with self.assertRaisesRegex(WorkerError, "identity changed while opening"):
                    RemoteEndpoint.load(target)

            self.assertTrue(did_swap())

    def test_certificate_replacement_between_lstat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "worker.pem"
            target.write_text("original", encoding="utf-8")
            replacement = root / "replacement.pem"
            replacement.write_text("replacement", encoding="utf-8")
            swapping_open, did_swap = self._replacement_open(target, replacement)

            with patch("psmatrix.remote_worker.os.open", side_effect=swapping_open):
                with self.assertRaisesRegex(WorkerError, "identity changed while opening"):
                    certificate_sha256(target)

            self.assertTrue(did_swap())

    def test_oversized_worker_config_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "worker.json"
            target.write_bytes(b"12345")

            with patch("psmatrix.remote_worker._MAX_REMOTE_CONFIG_BYTES", 4), patch(
                "psmatrix.remote_worker.os.open"
            ) as open_mock:
                with self.assertRaisesRegex(WorkerError, "configured read limit"):
                    WorkerConfig.load(target)

            open_mock.assert_not_called()

    def test_oversized_result_cache_entry_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, identity = _pin_direct_directory(Path(temp), label="Worker result cache")
            target = directory / "cached.json"
            target.write_bytes(b"12345")

            with patch("psmatrix.remote_worker._MAX_RESULT_CACHE_BYTES", 4), patch(
                "psmatrix.remote_worker.os.open"
            ) as open_mock:
                with self.assertRaisesRegex(WorkerError, "configured read limit"):
                    _read_pinned_json(
                        target,
                        directory=directory,
                        directory_identity=identity,
                        label="Worker result cache entry",
                    )

            open_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
