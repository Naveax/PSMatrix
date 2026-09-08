import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix.remote_protocol import create_job_request, create_job_result, request_sha256
from psmatrix.remote_worker import WorkerError, WorkerService
from psmatrix.signing import canonical_json_bytes, generate_ed25519_keypair


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if Path(path) in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class _WorkerConfig:
    def __init__(
        self,
        workspace_root: Path,
        *,
        controller_public_key: Path,
        signing_private_key: Path,
        signing_public_key: Path,
    ):
        self.workspace_root = workspace_root
        self.worker_id = "worker-a"
        self.controller_id = "controller-a"
        self.controller_certificate_sha256 = "a" * 64
        self.controller_public_key = controller_public_key
        self.signing_private_key = signing_private_key
        self.signing_public_key = signing_public_key

    def validate(self) -> None:
        return


def _fixture(root: Path):
    controller_private = root / "controller.pem"
    controller_public = root / "controller.pub"
    worker_private = root / "worker.pem"
    worker_public = root / "worker.pub"
    generate_ed25519_keypair(controller_private, controller_public)
    generate_ed25519_keypair(worker_private, worker_public)
    workspace = root / "workspace"
    workspace.mkdir()
    config = _WorkerConfig(
        workspace,
        controller_public_key=controller_public,
        signing_private_key=worker_private,
        signing_public_key=worker_public,
    )
    executor = Mock(return_value=(
        {"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": []},
        {"required": False, "before": {"passed": True}, "after": {"passed": True}},
    ))
    service = WorkerService(config, executor, lambda: {"worker_id": "worker-a", "authoritative": True})
    request = create_job_request(
        controller_id="controller-a",
        worker_id="worker-a",
        artifact=b"zip",
        entrypoint="tool.ps1",
        options={},
        private_key=controller_private,
        public_key=controller_public,
    )
    return service, executor, request, worker_private, worker_public


class WorkerRuntimeStatePathSecurityTests(unittest.TestCase):
    def test_service_rejects_reparse_results_directory_at_construction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            controller_private = root / "controller.pem"
            controller_public = root / "controller.pub"
            worker_private = root / "worker.pem"
            worker_public = root / "worker.pub"
            generate_ed25519_keypair(controller_private, controller_public)
            generate_ed25519_keypair(worker_private, worker_public)
            workspace = root / "workspace"
            workspace.mkdir()
            results = workspace / ".job-results"
            results.mkdir()
            config = _WorkerConfig(
                workspace,
                controller_public_key=controller_public,
                signing_private_key=worker_private,
                signing_public_key=worker_public,
            )
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {results})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WorkerService(config, Mock(), lambda: {})

    def test_cached_result_is_revalidated_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            service, executor, request, worker_private, worker_public = _fixture(root)
            result = create_job_result(
                request=request,
                worker_id="worker-a",
                capabilities={"worker_id": "worker-a", "authoritative": True},
                report={"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": []},
                private_key=worker_private,
                public_key=worker_public,
                reset={"required": False, "before": {"passed": True}, "after": {"passed": True}},
            )
            cache_path = service.results / f"{request['job_id']}.json"
            cache_path.write_text(json.dumps({
                "schema": 1,
                "request_sha256": request_sha256(request),
                "result_sha256": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
                "created_at": datetime.now(UTC).isoformat(),
                "result": result,
            }), encoding="utf-8")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {cache_path})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.process(request, "a" * 64)

            executor.assert_not_called()

    def test_process_revalidates_results_directory_before_executor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            service, executor, request, _worker_private, _worker_public = _fixture(root)
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {service.results})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.process(request, "a" * 64)

            executor.assert_not_called()

    def test_process_revalidates_workspace_root_before_state_access(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            service, executor, request, _worker_private, _worker_public = _fixture(root)
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {service.config.workspace_root})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.process(request, "a" * 64)

            executor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
