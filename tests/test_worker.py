import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.pki import create_ca, issue_certificate
from psmatrix.signing import TrustStore, generate_ed25519_keypair
from psmatrix.remote_protocol import create_job_request
from psmatrix.remote_worker import (
    RemoteEndpoint,
    WorkerConfig,
    WorkerError,
    WorkerService,
    build_worker_server,
    certificate_sha256,
    create_source_archive,
    submit_remote_job,
    WindowsJobExecutor,
)


def real_pwsh() -> Path:
    configured = os.environ.get("PSMATRIX_TEST_PWSH")
    candidates = [
        Path(configured) if configured else None,
        Path("/mnt/data/psmatrix/.psmatrix/runtimes/powershell-7.6.4-linux-x64/pwsh"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    return Path("/nonexistent/psmatrix-test-pwsh")


def certificates(root: Path) -> None:
    """Create worker TLS material through the product PKI implementation."""
    ca = create_ca(root / "tls-ca", common_name="PSMatrix Test CA", days=30)
    ca_certificate = Path(ca["certificate"])
    ca_private_key = Path(ca["private_key"])
    server = issue_certificate(
        ca_certificate,
        ca_private_key,
        root / "tls-server",
        common_name="localhost",
        role="server",
        dns_names=["localhost"],
        days=7,
    )
    client = issue_certificate(
        ca_certificate,
        ca_private_key,
        root / "tls-client",
        common_name="controller-a",
        role="client",
        days=7,
    )
    material = {
        root / "ca.pem": ca_certificate,
        root / "server.pem": Path(server["certificate"]),
        root / "server.key": Path(server["private_key"]),
        root / "client.pem": Path(client["certificate"]),
        root / "client.key": Path(client["private_key"]),
    }
    for destination, source in material.items():
        destination.write_bytes(source.read_bytes())


class WorkerTests(unittest.TestCase):
    def test_source_archive_rejects_symlink_and_root_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            archive = create_source_archive(project, [source])
            self.assertGreater(len(archive), 10)

            reserved = project / "CON.ps1"
            reserved.write_text("'bad'", encoding="utf-8")
            with self.assertRaises(WorkerError):
                create_source_archive(project, [reserved])

            upper = project / "Case.ps1"
            lower = project / "case.ps1"
            upper.write_text("'upper'", encoding="utf-8")
            lower.write_text("'lower'", encoding="utf-8")
            # A case-insensitive filesystem has already collapsed these into
            # one physical file, so there are not two archive entries to
            # reject. On a case-sensitive filesystem the archive layer must
            # reject the Windows-ambiguous pair.
            try:
                same_physical_file = os.path.samefile(upper, lower)
            except OSError:
                same_physical_file = False
            if not same_physical_file:
                with self.assertRaises(WorkerError):
                    create_source_archive(project, [upper, lower])

            outside = root / "outside.ps1"
            outside.write_text("'bad'", encoding="utf-8")
            with self.assertRaises(WorkerError):
                create_source_archive(project, [outside])

            if hasattr(os, "symlink"):
                link = project / "link.ps1"
                try:
                    link.symlink_to(source)
                except (OSError, NotImplementedError):
                    pass
                else:
                    with self.assertRaises(WorkerError):
                        create_source_archive(project, [link])

    def test_mtls_signed_job_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificates(root)
            cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
            wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            workspace = root / "workspace"
            config = WorkerConfig(
                worker_id="worker-a", host="127.0.0.1", port=0,
                tls_certificate=root / "server.pem", tls_private_key=root / "server.key", client_ca=root / "ca.pem",
                signing_private_key=wpriv, signing_public_key=wpub,
                controller_id="controller-a", controller_public_key=cpub,
                controller_certificate_sha256=certificate_sha256(root / "client.pem"),
                workspace_root=workspace, powershell_executable="unused", expected_version="5.1", reset_required=False,
            )

            def execute(request, artifact):
                self.assertGreater(len(artifact), 10)
                return (
                    {"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": [{"status": "PASS"}]},
                    {"required": False, "before": {"passed": True}, "after": {"passed": True}},
                )

            service = WorkerService(
                config,
                execute,
                lambda: {"worker_id": "worker-a", "runtime_id": "windows-powershell-5.1", "authoritative": True},
            )
            server = build_worker_server(service)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            endpoint = RemoteEndpoint(
                url=f"https://localhost:{server.server_address[1]}", worker_id="worker-a", controller_id="controller-a",
                controller_certificate=root / "client.pem", controller_private_key=root / "client.key", server_ca=root / "ca.pem",
                controller_signing_private_key=cpriv, controller_signing_public_key=cpub,
                worker_signing_public_key=wpub, expected_server_certificate_sha256=certificate_sha256(root / "server.pem"),
                expected_runtime_id="windows-powershell-5.1",
            )
            try:
                result = submit_remote_job(
                    endpoint,
                    root=project,
                    files=[source],
                    entrypoint=source,
                    options={},
                    timeout=30,
                )
                self.assertTrue(result["valid"])
                self.assertEqual(result["report"]["status"], "PASS")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_worker_replays_cached_signed_result_without_duplicate_execution(self):
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
                workspace_root=root / "workspace", powershell_executable="unused", expected_version="5.1", reset_required=False,
            )
            calls = []

            def execute(request, artifact):
                calls.append(request["job_id"])
                return (
                    {"schema": 1, "status": "PASS", "worker_id": "worker-a", "targets": []},
                    {"required": False, "before": {"passed": True}, "after": {"passed": True}},
                )

            service = WorkerService(
                config,
                execute,
                lambda: {"worker_id": "worker-a", "runtime_id": "windows-powershell-5.1", "authoritative": True},
            )
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text("'ok'", encoding="utf-8")
            archive = create_source_archive(project, [source])
            request = create_job_request(
                controller_id="controller-a", worker_id="worker-a", artifact=archive,
                entrypoint="tool.ps1", options={}, private_key=cpriv, public_key=cpub,
                job_id="00000000-0000-0000-0000-000000000099", nonce="n" * 32,
            )
            peer = certificate_sha256(root / "client.pem")
            first = service.process(request, peer)
            second = service.process(request, peer)
            self.assertEqual(first, second)
            self.assertEqual(calls, [request["job_id"]])

    def test_endpoint_load_uses_trust_store_key_and_certificate_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificates(root)
            controller_private, controller_public = root / "controller-sign.pem", root / "controller-sign.pub"
            worker_private, worker_public = root / "worker-sign.pem", root / "worker-sign.pub"
            generate_ed25519_keypair(controller_private, controller_public)
            generate_ed25519_keypair(worker_private, worker_public)
            trust_home = root / "home"
            trusted = TrustStore(trust_home).add(
                "windows-powershell-5.1-a", "worker", worker_public,
                certificate=root / "server.pem",
            )
            config_dir = root / "config"
            config_dir.mkdir()
            secrets = root / "secrets"
            secrets.mkdir()
            for source, name in (
                (root / "client.pem", "client.pem"),
                (root / "client.key", "client.key"),
                (root / "ca.pem", "ca.pem"),
                (controller_private, "controller-private.pem"),
                (controller_public, "controller-public.pem"),
            ):
                (secrets / name).write_bytes(source.read_bytes())
            endpoint_path = config_dir / "endpoint.json"
            endpoint_path.write_text(
                json.dumps({
                    "schema": 1,
                    "url": "https://localhost:9443",
                    "worker_id": "windows-powershell-5.1-a",
                    "runtime_id": "windows-powershell-5.1",
                    "controller_id": "controller-a",
                    "tls": {
                        "certificate": "../secrets/client.pem",
                        "private_key": "../secrets/client.key",
                        "server_ca": "../secrets/ca.pem",
                    },
                    "controller_signing": {
                        "private_key": "../secrets/controller-private.pem",
                        "public_key": "../secrets/controller-public.pem",
                    },
                    "worker_signing": {"identity": "windows-powershell-5.1-a"},
                }),
                encoding="utf-8",
            )
            endpoint = RemoteEndpoint.load(endpoint_path, trust_home=trust_home)
            self.assertEqual(endpoint.worker_signing_public_key, trusted.public_key)
            self.assertEqual(endpoint.expected_server_certificate_sha256, trusted.certificate_sha256)
            self.assertEqual(endpoint.expected_runtime_id, "windows-powershell-5.1")

    def test_core_worker_probe_uses_exact_windows_core_runtime_id(self):
        payload = json.dumps({
            "version": "7.6.4",
            "edition": "Core",
            "platform": "Windows_NT",
            "is_windows": True,
            "is64bit": True,
            "commands": {},
            "providers": [],
            "modules": [],
        })
        completed = subprocess.CompletedProcess(
            ["pwsh-core"], 0, stdout=payload + "\n", stderr=""
        )
        from psmatrix.remote_worker import probe_windows_powershell

        with patch(
            "psmatrix.remote_worker._run_process_tree",
            return_value=completed,
        ) as process_probe:
            capability = probe_windows_powershell("pwsh-core", "7.6.4")
        process_probe.assert_called_once()
        self.assertEqual(capability["runtime_id"], "powershell-7.6.4-windows-x64")
        self.assertTrue(capability["authoritative"])

    def test_non_windows_probe_is_not_authoritative(self):
        pwsh = real_pwsh()
        if not pwsh.is_file():
            self.skipTest("real PowerShell 7.6.4 runtime unavailable")
        from psmatrix.remote_worker import probe_windows_powershell

        with self.assertRaises(WorkerError):
            probe_windows_powershell(str(pwsh), "7.6.4")
        capability = probe_windows_powershell(
            str(pwsh), "7.6.4", require_windows=False
        )
        self.assertFalse(capability["authoritative"])

    def test_snapshot_reset_is_fail_closed_and_harness_runs_with_real_pwsh_when_available(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pwsh = real_pwsh()
            if not pwsh.is_file():
                self.skipTest("real PowerShell 7.6.4 runtime unavailable")
            project = root / "project"
            project.mkdir()
            source = project / "tool.ps1"
            source.write_text(
                "param([string]$Name)\nSet-Content -LiteralPath output.txt -Value $Name\nWrite-Warning 'warn'\n",
                encoding="utf-8",
            )
            archive = create_source_archive(project, [source])
            base = dict(
                worker_id="worker-local", host="127.0.0.1", port=0,
                tls_certificate=root / "missing-server.pem", tls_private_key=root / "missing-server.key", client_ca=root / "missing-ca.pem",
                signing_private_key=root / "missing-sign.pem", signing_public_key=root / "missing-sign.pub",
                controller_id="controller", controller_public_key=root / "missing-controller.pub", controller_certificate_sha256="0" * 64,
                workspace_root=root / "workspace", powershell_executable=str(pwsh), expected_version="7.6.4",
                allow_non_windows_for_testing=True,
            )
            missing_reset = WindowsJobExecutor(
                WorkerConfig(**base, reset_required=True),
                Path("src/psmatrix/windows_worker.ps1"),
            )
            report, reset = missing_reset(
                {
                    "job_id": "00000000-0000-0000-0000-000000000001",
                    "entrypoint": "tool.ps1",
                    "options": {},
                },
                archive,
            )
            self.assertEqual(report["status"], "FAIL_RESET")
            self.assertFalse(reset["before"]["passed"])

            configured_values = dict(base)
            configured_values["workspace_root"] = root / "workspace2"
            configured = WindowsJobExecutor(
                WorkerConfig(
                    **configured_values,
                    reset_required=True,
                    reset_before=("bash", "-lc", "true"),
                    reset_after=("bash", "-lc", "true"),
                ),
                Path("src/psmatrix/windows_worker.ps1"),
            )
            report, reset = configured(
                {
                    "job_id": "00000000-0000-0000-0000-000000000002",
                    "entrypoint": "tool.ps1",
                    "options": {
                        "parameters": {"Name": "verified"},
                        "verification": [{"kind": "file_exists", "path": "output.txt"}],
                        "timeout_seconds": 60,
                    },
                },
                archive,
            )
            self.assertEqual(report["status"], "PASS", report)
            self.assertTrue(reset["before"]["passed"] and reset["after"]["passed"])
            target = report["targets"][0]
            self.assertEqual(target["status"], "PASS")
            self.assertEqual(target["verification"][0]["passed"], True)
            self.assertIn("warn", target["observation"]["streams"]["warning"])


if __name__ == "__main__":
    unittest.main()
