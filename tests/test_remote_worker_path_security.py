import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix.remote_worker import RemoteEndpoint, WorkerConfig, WorkerError, _client_context


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
        "reset": {
            "required": True,
            "before": ["reset-before.cmd"],
            "after": ["reset-after.cmd"],
        },
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


def _materialize_worker_files(root: Path) -> None:
    for name in (
        "worker-cert.pem",
        "worker-key.pem",
        "controller-ca.pem",
        "worker-signing-private.pem",
        "worker-signing-public.pem",
        "controller-signing-public.pem",
    ):
        _touch(root, name)


def _materialize_endpoint_files(root: Path) -> None:
    for name in (
        "controller-cert.pem",
        "controller-key.pem",
        "worker-ca.pem",
        "controller-signing-private.pem",
        "controller-signing-public.pem",
        "worker-signing-public.pem",
    ):
        _touch(root, name)


class RemoteWorkerPathSecurityTests(unittest.TestCase):
    def test_worker_config_rejects_reparse_config_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_worker_files(root)
            config_path = root / "worker.json"
            config_path.write_text(json.dumps(_worker_payload()), encoding="utf-8")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {config_path})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WorkerConfig.load(config_path)

    def test_worker_config_rejects_reparse_tls_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_worker_files(root)
            config_path = root / "worker.json"
            config_path.write_text(json.dumps(_worker_payload()), encoding="utf-8")
            marked = root / "worker-key.pem"
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {marked})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WorkerConfig.load(config_path)

    def test_worker_config_rejects_reparse_workspace_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_worker_files(root)
            workspace = root / "workspaces"
            workspace.mkdir()
            config_path = root / "worker.json"
            config_path.write_text(json.dumps(_worker_payload()), encoding="utf-8")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {workspace})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WorkerConfig.load(config_path)

    def test_remote_endpoint_rejects_reparse_config_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_endpoint_files(root)
            endpoint_path = root / "endpoint.json"
            endpoint_path.write_text(json.dumps(_endpoint_payload()), encoding="utf-8")
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {endpoint_path})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    RemoteEndpoint.load(endpoint_path)

    def test_remote_endpoint_rejects_reparse_trust_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_endpoint_files(root)
            endpoint_path = root / "endpoint.json"
            endpoint_path.write_text(json.dumps(_endpoint_payload()), encoding="utf-8")
            marked = root / "worker-ca.pem"
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {marked})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    RemoteEndpoint.load(endpoint_path)

    def test_client_context_revalidates_tls_paths_after_endpoint_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _materialize_endpoint_files(root)
            endpoint_path = root / "endpoint.json"
            endpoint_path.write_text(json.dumps(_endpoint_payload()), encoding="utf-8")
            endpoint = RemoteEndpoint.load(endpoint_path)

            marked = endpoint.controller_private_key
            original_lstat = Path.lstat
            fake_context = Mock()
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {marked})), \
                 patch("psmatrix.remote_worker.ssl.create_default_context", return_value=fake_context):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    _client_context(endpoint)
            fake_context.load_cert_chain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
