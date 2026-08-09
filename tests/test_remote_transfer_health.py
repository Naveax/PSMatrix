import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from psmatrix.pki import create_ca, issue_certificate
from psmatrix.remote_worker import (
    RemoteEndpoint,
    WorkerConfig,
    WorkerService,
    build_worker_server,
    certificate_sha256,
    probe_remote_endpoint,
    submit_remote_job,
    WorkerError,
    _https_exchange_retry,
)
from psmatrix.signing import generate_ed25519_keypair


def certificates(root: Path) -> dict[str, Path]:
    ca = create_ca(root / "ca", common_name="Transfer CA", days=30)
    ca_certificate = Path(ca["certificate"])
    ca_private_key = Path(ca["private_key"])
    server = issue_certificate(
        ca_certificate,
        ca_private_key,
        root / "server",
        common_name="localhost",
        role="server",
        dns_names=["localhost"],
        days=7,
    )
    client = issue_certificate(
        ca_certificate,
        ca_private_key,
        root / "client",
        common_name="controller-a",
        role="client",
        days=7,
    )
    return {
        "ca": ca_certificate,
        "server_certificate": Path(server["certificate"]),
        "server_private_key": Path(server["private_key"]),
        "client_certificate": Path(client["certificate"]),
        "client_private_key": Path(client["private_key"]),
    }


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
            tls = certificates(root)
            cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
            wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            config = WorkerConfig(
                worker_id="worker-a", host="127.0.0.1", port=0,
                tls_certificate=tls["server_certificate"], tls_private_key=tls["server_private_key"], client_ca=tls["ca"],
                signing_private_key=wpriv, signing_public_key=wpub,
                controller_id="controller-a", controller_public_key=cpub,
                controller_certificate_sha256=certificate_sha256(tls["client_certificate"]),
                workspace_root=root / "workspace", powershell_executable="unused", expected_version="5.1",
                reset_required=False, inline_artifact_limit=64 * 1024, transfer_chunk_size=64 * 1024,
            )
            captured = {}

            def execute(request, artifact):
                captured["artifact_size"] = len(artifact)
                return (
                    {"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": [{"status": "PASS"}]},
                    {"required": False, "before": {"passed": True}, "after": {"passed": True}},
                )

            capabilities = lambda: {
                "worker_id": "worker-a",
                "runtime_id": "windows-powershell-5.1",
                "authoritative": True,
                "version": "5.1",
            }
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
                controller_certificate=tls["client_certificate"], controller_private_key=tls["client_private_key"], server_ca=tls["ca"],
                controller_signing_private_key=cpriv, controller_signing_public_key=cpub, worker_signing_public_key=wpub,
                expected_server_certificate_sha256=certificate_sha256(tls["server_certificate"]), expected_runtime_id="windows-powershell-5.1",
                inline_artifact_limit=64 * 1024, transfer_chunk_size=64 * 1024,
            )
            try:
                health = probe_remote_endpoint(endpoint)
                self.assertTrue(health["valid"])
                result = submit_remote_job(endpoint, root=project, files=[source, payload], entrypoint=source, options={}, timeout=30)
                self.assertEqual(result["transfer"]["mode"], "resumable")
                self.assertGreater(captured["artifact_size"], 64 * 1024)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
