import os
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from psmatrix.remote_worker import (
    RemoteEndpoint, WorkerConfig, WorkerService, build_worker_server,
    certificate_sha256, probe_remote_endpoint, submit_remote_job,
    WorkerError, _https_exchange_retry,
)
from psmatrix.signing import generate_ed25519_keypair


def run(args, cwd):
    subprocess.run(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def certificates(root: Path):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=Transfer CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], root)
    (root / "server.ext").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost"], root)
    run(["openssl", "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext"], root)
    (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n", encoding="utf-8")
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/CN=controller-a"], root)
    run(["openssl", "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "1", "-extfile", "client.ext"], root)


class RemoteTransferHealthTests(unittest.TestCase):
    def test_transport_retry_is_bounded_and_trust_errors_are_not_retried(self):
        endpoint = object()
        with patch("psmatrix.remote_worker._https_exchange", side_effect=[
            WorkerError("Remote worker request failed: reset-1"),
            WorkerError("Remote worker request failed: reset-2"),
            (200, b"ok"),
        ]) as exchange, patch("psmatrix.remote_worker.time.sleep"):
            self.assertEqual(
                _https_exchange_retry(endpoint, "GET", "/v1/health", body=None, headers={}, timeout=1),
                (200, b"ok"),
            )
            self.assertEqual(exchange.call_count, 3)
        with patch("psmatrix.remote_worker._https_exchange", side_effect=WorkerError("Worker TLS certificate fingerprint mismatch")) as exchange:
            with self.assertRaises(WorkerError):
                _https_exchange_retry(endpoint, "GET", "/v1/health", body=None, headers={}, timeout=1)
            self.assertEqual(exchange.call_count, 1)

    def test_signed_health_and_resumable_job(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificates(root)
            cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
            wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            config = WorkerConfig(
                worker_id="worker-a", host="127.0.0.1", port=0,
                tls_certificate=root / "server.pem", tls_private_key=root / "server.key", client_ca=root / "ca.pem",
                signing_private_key=wpriv, signing_public_key=wpub,
                controller_id="controller-a", controller_public_key=cpub,
                controller_certificate_sha256=certificate_sha256(root / "client.pem"),
                workspace_root=root / "workspace", powershell_executable="unused", expected_version="5.1",
                reset_required=False, inline_artifact_limit=64 * 1024, transfer_chunk_size=64 * 1024,
            )
            captured = {}
            def execute(request, artifact):
                captured["artifact_size"] = len(artifact)
                return ({"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": [{"status": "PASS"}]}, {"required": False, "before": {"passed": True}, "after": {"passed": True}})
            capabilities = lambda: {"worker_id": "worker-a", "runtime_id": "windows-powershell-5.1", "authoritative": True, "version": "5.1"}
            server = build_worker_server(WorkerService(config, execute, capabilities))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            payload = project / "payload.bin"
            payload.write_bytes(os.urandom(180000))
            endpoint = RemoteEndpoint(
                url=f"https://localhost:{server.server_address[1]}", worker_id="worker-a", controller_id="controller-a",
                controller_certificate=root / "client.pem", controller_private_key=root / "client.key", server_ca=root / "ca.pem",
                controller_signing_private_key=cpriv, controller_signing_public_key=cpub, worker_signing_public_key=wpub,
                expected_server_certificate_sha256=certificate_sha256(root / "server.pem"), expected_runtime_id="windows-powershell-5.1",
                inline_artifact_limit=64 * 1024, transfer_chunk_size=64 * 1024,
            )
            try:
                health = probe_remote_endpoint(endpoint)
                self.assertTrue(health["valid"])
                result = submit_remote_job(endpoint, root=project, files=[source, payload], entrypoint=source, options={}, timeout=30)
                self.assertEqual(result["transfer"]["mode"], "resumable")
                self.assertGreater(captured["artifact_size"], 64 * 1024)
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
