import io
import json
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix.remote_worker import (
    RemoteEndpoint,
    WindowsJobExecutor,
    WorkerConfig,
    WorkerError,
    WorkerService,
    probe_remote_endpoint,
    submit_remote_job,
)


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _touch(root: Path, name: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("placeholder", encoding="utf-8")
    return path


def _worker_payload() -> dict:
    return {
        "schema": 1,
        "worker_id": "worker-51",
        "host": "127.0.0.1",
        "port": 9443,
        "tls": {
            "certificate": "worker-cert.pem",
            "private_key": "worker-key.pem",
            "client_ca": "controller-ca.pem",
        },
        "signing": {
            "private_key": "worker-signing-private.pem",
            "public_key": "worker-signing-public.pem",
        },
        "controller": {
            "identity": "controller-1",
            "public_key": "controller-signing-public.pem",
            "certificate_sha256": "a" * 64,
        },
        "workspace_root": "workspaces",
        "runtime": {"executable": "powershell.exe", "version": "5.1"},
        "reset": {"required": False},
    }


def _endpoint_payload() -> dict:
    return {
        "schema": 1,
        "url": "https://127.0.0.1:9443",
        "worker_id": "worker-51",
        "controller_id": "controller-1",
        "runtime_id": "windows-powershell-5.1",
        "tls": {
            "certificate": "controller-cert.pem",
            "private_key": "controller-key.pem",
            "server_ca": "worker-ca.pem",
            "server_certificate_sha256": "b" * 64,
        },
        "controller_signing": {
            "private_key": "controller-signing-private.pem",
            "public_key": "controller-signing-public.pem",
        },
        "worker_signing": {"public_key": "worker-signing-public.pem"},
    }


def _load_worker(root: Path) -> WorkerConfig:
    for name in (
        "worker-cert.pem",
        "worker-key.pem",
        "controller-ca.pem",
        "worker-signing-private.pem",
        "worker-signing-public.pem",
        "controller-signing-public.pem",
    ):
        _touch(root, name)
    config_path = root / "worker.json"
    config_path.write_text(json.dumps(_worker_payload()), encoding="utf-8")
    return WorkerConfig.load(config_path)


def _load_endpoint(root: Path) -> RemoteEndpoint:
    for name in (
        "controller-cert.pem",
        "controller-key.pem",
        "worker-ca.pem",
        "controller-signing-private.pem",
        "controller-signing-public.pem",
        "worker-signing-public.pem",
    ):
        _touch(root, name)
    endpoint_path = root / "endpoint.json"
    endpoint_path.write_text(json.dumps(_endpoint_payload()), encoding="utf-8")
    return RemoteEndpoint.load(endpoint_path)


def _source_archive() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("main.ps1", "'ok'\n")
    return output.getvalue()


class RemoteWorkerUseTimePathSecurityTests(unittest.TestCase):
    def test_windows_executor_rejects_reparse_harness_at_construction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = _load_worker(root)
            harness = _touch(root, "worker-harness.ps1")
            original_lstat = Path.lstat

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {harness})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WindowsJobExecutor(config, harness)

    def test_windows_executor_revalidates_harness_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = _load_worker(root)
            harness = _touch(root, "worker-harness.ps1")
            executor = WindowsJobExecutor(config, harness)
            original_lstat = Path.lstat
            process_probe = Mock()
            request = {
                "job_id": str(uuid.uuid4()),
                "entrypoint": "main.ps1",
                "options": {"timeout_seconds": 30},
            }

            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {harness})), \
                 patch("psmatrix.remote_worker._run_process_tree", process_probe):
                report, reset = executor(request, _source_archive())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("symlink or reparse point", report["worker_error"])
            self.assertFalse(reset["required"])
            process_probe.assert_not_called()

    def test_worker_health_revalidates_signing_key_before_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = _load_worker(root)
            service = WorkerService(
                config,
                Mock(),
                lambda: {"worker_id": config.worker_id, "authoritative": True},
            )
            original_lstat = Path.lstat
            envelope_probe = Mock(return_value={})

            with patch.object(
                Path,
                "lstat",
                _reparse_lstat(original_lstat, {config.signing_private_key}),
            ), patch("psmatrix.remote_worker.create_dsse_envelope", envelope_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.signed_health()

            envelope_probe.assert_not_called()

    def test_worker_process_revalidates_controller_key_before_request_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = _load_worker(root)
            service = WorkerService(
                config,
                Mock(),
                lambda: {"worker_id": config.worker_id, "authoritative": True},
            )
            request = {
                "controller_id": config.controller_id,
                "worker_id": config.worker_id,
                "job_id": str(uuid.uuid4()),
            }
            original_lstat = Path.lstat
            verify_probe = Mock(return_value=b"artifact")

            with patch.object(
                Path,
                "lstat",
                _reparse_lstat(original_lstat, {config.controller_public_key}),
            ), patch("psmatrix.remote_worker.verify_job_request", verify_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.process(request, config.controller_certificate_sha256)

            verify_probe.assert_not_called()

    def test_worker_process_revalidates_worker_signing_key_before_result_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = _load_worker(root)
            executor = Mock(return_value=({"schema": 1, "status": "PASS"}, {"required": False}))
            service = WorkerService(
                config,
                executor,
                lambda: {"worker_id": config.worker_id, "authoritative": True},
            )
            request = {
                "controller_id": config.controller_id,
                "worker_id": config.worker_id,
                "job_id": str(uuid.uuid4()),
            }
            original_lstat = Path.lstat
            result_probe = Mock(return_value={})

            with patch("psmatrix.remote_worker.verify_job_request", return_value=b"artifact"), \
                 patch.object(
                     Path,
                     "lstat",
                     _reparse_lstat(original_lstat, {config.signing_private_key}),
                 ), \
                 patch("psmatrix.remote_worker.create_job_result", result_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    service.process(request, config.controller_certificate_sha256)

            executor.assert_called_once()
            result_probe.assert_not_called()

    def test_endpoint_health_revalidates_worker_signing_key_before_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            endpoint = _load_endpoint(root)
            body = json.dumps(
                {"worker_id": endpoint.worker_id, "attestation": {"payload": "placeholder"}}
            ).encode("utf-8")
            original_lstat = Path.lstat
            verify_probe = Mock()

            with patch("psmatrix.remote_worker._https_exchange_retry", return_value=(200, body)), \
                 patch.object(
                     Path,
                     "lstat",
                     _reparse_lstat(original_lstat, {endpoint.worker_signing_public_key}),
                 ), \
                 patch("psmatrix.remote_worker.verify_dsse_envelope", verify_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    probe_remote_endpoint(endpoint)

            verify_probe.assert_not_called()

    def test_submit_revalidates_controller_signing_key_before_request_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            endpoint = _load_endpoint(root)
            project = root / "project"
            project.mkdir()
            source = _touch(project, "main.ps1")
            original_lstat = Path.lstat
            request_probe = Mock(return_value={})

            with patch.object(
                Path,
                "lstat",
                _reparse_lstat(original_lstat, {endpoint.controller_signing_private_key}),
            ), patch("psmatrix.remote_worker.create_job_request", request_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    submit_remote_job(
                        endpoint,
                        root=project,
                        files=[source],
                        entrypoint=source,
                        options={},
                    )

            request_probe.assert_not_called()

    def test_submit_revalidates_worker_signing_key_before_result_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            endpoint = _load_endpoint(root)
            project = root / "project"
            project.mkdir()
            source = _touch(project, "main.ps1")
            original_lstat = Path.lstat
            verify_probe = Mock()

            with patch("psmatrix.remote_worker.create_job_request", return_value={"schema": 1}), \
                 patch("psmatrix.remote_worker._https_exchange_retry", return_value=(200, b"{}")), \
                 patch.object(
                     Path,
                     "lstat",
                     _reparse_lstat(original_lstat, {endpoint.worker_signing_public_key}),
                 ), \
                 patch("psmatrix.remote_worker.verify_job_result", verify_probe):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    submit_remote_job(
                        endpoint,
                        root=project,
                        files=[source],
                        entrypoint=source,
                        options={},
                    )

            verify_probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
