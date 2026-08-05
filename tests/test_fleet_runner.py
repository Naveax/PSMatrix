import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from psmatrix.fleet import FleetRegistry
from psmatrix.fleet_runner import execute_managed_fleet_job
from psmatrix.remote_worker import WorkerConfig, WorkerService, build_worker_server, certificate_sha256
from psmatrix.signing import TrustStore, generate_ed25519_keypair


def run(args, cwd):
    subprocess.run(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def certificates(root: Path):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=Fleet Runner CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], root)
    (root / "server.ext").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost"], root)
    run(["openssl", "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext"], root)
    (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n", encoding="utf-8")
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/CN=controller-a"], root)
    run(["openssl", "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "1", "-extfile", "client.ext"], root)


class FleetRunnerTests(unittest.TestCase):
    def test_controller_managed_snapshot_and_signed_worker_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            certificates(root)
            cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
            wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
            rpriv, rpub = root / "reset-sign.pem", root / "reset-sign.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            generate_ed25519_keypair(rpriv, rpub)
            config = WorkerConfig(
                worker_id="worker-a", host="127.0.0.1", port=0,
                tls_certificate=root / "server.pem", tls_private_key=root / "server.key", client_ca=root / "ca.pem",
                signing_private_key=wpriv, signing_public_key=wpub,
                controller_id="controller-a", controller_public_key=cpub,
                controller_certificate_sha256=certificate_sha256(root / "client.pem"),
                workspace_root=root / "workspace", powershell_executable="unused", expected_version="5.1", reset_required=False,
            )
            def execute(request, artifact):
                return ({"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": [{"status": "PASS"}]}, {"required": False, "before": {"passed": True}, "after": {"passed": True}})
            capabilities = lambda: {"worker_id": "worker-a", "runtime_id": "windows-powershell-5.1", "authoritative": True, "version": "5.1"}
            server = build_worker_server(WorkerService(config, execute, capabilities))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            TrustStore(home).add("worker-a", "worker", wpub, certificate=root / "server.pem")
            endpoint = root / "endpoint.json"
            endpoint.write_text(json.dumps({
                "schema": 1, "url": f"https://localhost:{server.server_address[1]}", "worker_id": "worker-a",
                "runtime_id": "windows-powershell-5.1", "controller_id": "controller-a",
                "tls": {"certificate": "client.pem", "private_key": "client.key", "server_ca": "ca.pem"},
                "controller_signing": {"private_key": "controller-sign.pem", "public_key": "controller-sign.pub"},
                "worker_signing": {"identity": "worker-a"}
            }), encoding="utf-8")
            state = root / "vm-state.txt"
            state.write_text("dirty", encoding="utf-8")
            restore = root / "restore.py"
            restore.write_text("from pathlib import Path\nPath('vm-state.txt').write_text('clean')\n", encoding="utf-8")
            measure = root / "measure.py"
            measure.write_text("import json\nfrom pathlib import Path\nprint(json.dumps({'state':Path('vm-state.txt').read_text()}))\n", encoding="utf-8")
            snapshot = root / "snapshot.json"
            snapshot.write_text(json.dumps({
                "schema": 1, "adapter_id": "test", "provider": "command-test", "worker_id": "worker-a",
                "vm_id": "vm-a", "snapshot_id": "clean", "cwd": ".", "timeout_seconds": 30,
                "restore_command": [sys.executable, str(restore)], "measure_command": [sys.executable, str(measure)]
            }), encoding="utf-8")
            project = root / "project"; project.mkdir()
            source = project / "tool.ps1"; source.write_text("'ok'", encoding="utf-8")
            registry = FleetRegistry(home)
            registry.enroll(endpoint, snapshot_config=snapshot, reset_private_key=rpriv, reset_public_key=rpub)
            try:
                result = execute_managed_fleet_job(
                    registry, worker_id="worker-a", root=project, files=[source], entrypoint=source, options={}, timeout=30
                )
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["snapshot_reset"]["before"]["verification"]["valid"])
                self.assertTrue(result["snapshot_reset"]["after"]["verification"]["valid"])
                self.assertEqual(registry.get("worker-a")["state"], "ACTIVE")
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
