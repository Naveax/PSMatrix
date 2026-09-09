import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix.remote_worker import (
    WorkerError,
    WorkerService,
    _pin_direct_directory,
    _read_pinned_json,
    _write_pinned_json,
)
from psmatrix.signing import canonical_json_bytes


_REPARSE_POINT = 0x400


class _Config:
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.worker_id = "worker-51"
        self.controller_id = "controller-1"
        self.controller_certificate_sha256 = "aa" * 32
        self.controller_public_key = workspace_root / "controller.pub"
        self.signing_public_key = workspace_root / "worker.pub"
        self.signing_private_key = workspace_root / "worker.key"

    def validate(self) -> None:
        return


def _service(root: Path, executor: Mock | None = None) -> WorkerService:
    executor = executor or Mock()
    with patch("psmatrix.remote_worker.ReplayGuard"), patch("psmatrix.remote_worker.TransferStore"):
        return WorkerService(_Config(root), executor, lambda: {"worker_id": "worker-51"})


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_nlink=getattr(info, "st_nlink", 1),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class RemoteWorkerResultCacheSecurityTests(unittest.TestCase):
    def test_pinned_cache_round_trip_accepts_direct_single_link_file(self):
        with tempfile.TemporaryDirectory() as temp:
            results = Path(temp) / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            path = results / f"{uuid.uuid4()}.json"
            value = {"schema": 1, "result": {"status": "PASS"}}

            _write_pinned_json(
                path,
                value,
                directory=results,
                directory_identity=identity,
                label="Worker result cache entry",
            )

            self.assertEqual(
                _read_pinned_json(
                    path,
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                ),
                value,
            )
            self.assertEqual(path.stat().st_nlink, 1)

    def test_cache_read_rejects_reparse_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            results = Path(temp) / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            path = results / f"{uuid.uuid4()}.json"
            path.write_text("{}\n", encoding="utf-8")

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {path})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    _read_pinned_json(
                        path,
                        directory=results,
                        directory_identity=identity,
                        label="Worker result cache entry",
                    )

    def test_cache_read_rejects_symlink_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            results = root / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            target = root / "outside.json"
            target.write_text("{}\n", encoding="utf-8")
            path = results / f"{uuid.uuid4()}.json"
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                _read_pinned_json(
                    path,
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )

    def test_cache_read_rejects_hardlinked_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            results = root / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            source = root / "outside.json"
            source.write_text("{}\n", encoding="utf-8")
            path = results / f"{uuid.uuid4()}.json"
            try:
                os.link(source, path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(WorkerError, "exactly one hard link"):
                _read_pinned_json(
                    path,
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )

    def test_cache_rejects_direct_directory_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            results = root / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            original = root / "original-results"
            os.replace(results, original)
            results.mkdir()

            with self.assertRaisesRegex(WorkerError, "directory identity changed"):
                _read_pinned_json(
                    results / f"{uuid.uuid4()}.json",
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )
            with self.assertRaisesRegex(WorkerError, "directory identity changed"):
                _write_pinned_json(
                    results / f"{uuid.uuid4()}.json",
                    {"schema": 1},
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )

    def test_cache_write_does_not_clobber_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            results = Path(temp) / "results"
            results.mkdir()
            results, identity = _pin_direct_directory(results, label="Worker result cache")
            path = results / f"{uuid.uuid4()}.json"
            path.write_text('{"owned": true}\n', encoding="utf-8")

            with self.assertRaisesRegex(WorkerError, "already exists"):
                _write_pinned_json(
                    path,
                    {"schema": 1},
                    directory=results,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"owned": True})

    def test_worker_service_preserves_normal_cache_hit_behavior(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executor = Mock()
            service = _service(root, executor)
            job_id = str(uuid.uuid4())
            request = {"job_id": job_id, "controller_id": "controller-1"}
            digest = "bb" * 32
            result = {"schema": 1, "status": "PASS", "worker_id": "worker-51"}
            cache_value = {
                "schema": 1,
                "request_sha256": digest,
                "result_sha256": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
                "created_at": "2026-09-08T00:00:00+00:00",
                "result": result,
            }
            _write_pinned_json(
                service.results / f"{job_id}.json",
                cache_value,
                directory=service.results,
                directory_identity=service.results_identity,
                label="Worker result cache entry",
            )

            with patch("psmatrix.remote_worker.request_sha256", return_value=digest), \
                 patch("psmatrix.remote_worker.verify_job_request") as verify_request, \
                 patch("psmatrix.remote_worker.verify_job_result") as verify_result:
                returned = service.process(request, "aa" * 32)

            self.assertEqual(returned, result)
            executor.assert_not_called()
            verify_request.assert_called_once()
            verify_result.assert_called_once()

    def test_worker_service_fails_closed_after_result_directory_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executor = Mock()
            service = _service(root, executor)
            old_results = root / "old-results"
            os.replace(service.results, old_results)
            service.results.mkdir()
            request = {"job_id": str(uuid.uuid4()), "controller_id": "controller-1"}

            with patch("psmatrix.remote_worker.request_sha256", return_value="cc" * 32), \
                 patch("psmatrix.remote_worker.verify_job_request") as verify_request:
                with self.assertRaisesRegex(WorkerError, "directory identity changed"):
                    service.process(request, "aa" * 32)

            verify_request.assert_not_called()
            executor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
