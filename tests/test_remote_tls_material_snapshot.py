import os
import stat
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_tls_material_hardening as hardening
from psmatrix import remote_worker as rw


@dataclass(frozen=True)
class _ServerConfig:
    tls_certificate: Path
    tls_private_key: Path
    client_ca: Path


@dataclass(frozen=True)
class _Endpoint:
    server_ca: Path
    controller_certificate: Path
    controller_private_key: Path


class _Service:
    def __init__(self, config):
        self.config = config


class RemoteTlsMaterialHardeningTests(unittest.TestCase):
    def _material_files(self, root: Path):
        cert = root / "cert.pem"
        key = root / "key.pem"
        ca = root / "ca.pem"
        cert.write_bytes(b"certificate-v1")
        key.write_bytes(b"private-key-v1")
        ca.write_bytes(b"ca-v1")
        return cert, key, ca

    def test_snapshot_copies_identity_safe_bytes_into_private_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key, ca = self._material_files(root)
            escaped_paths = []
            with hardening._tls_material_snapshot(
                rw,
                {
                    "server-cert.pem": (cert, "Worker TLS certificate"),
                    "server-key.pem": (key, "Worker TLS private key"),
                    "client-ca.pem": (ca, "Controller client CA"),
                },
            ) as snapshot:
                escaped_paths = list(snapshot.values())
                self.assertEqual(snapshot["server-cert.pem"].read_bytes(), b"certificate-v1")
                self.assertEqual(snapshot["server-key.pem"].read_bytes(), b"private-key-v1")
                self.assertEqual(snapshot["client-ca.pem"].read_bytes(), b"ca-v1")
                self.assertNotEqual(snapshot["server-cert.pem"], cert)
                if os.name != "nt":
                    self.assertEqual(
                        stat.S_IMODE(snapshot["server-key.pem"].stat().st_mode),
                        0o600,
                    )
            self.assertTrue(all(not path.exists() for path in escaped_paths))

    def test_server_builder_loads_snapshot_and_restores_original_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key, ca = self._material_files(root)
            config = _ServerConfig(cert, key, ca)
            service = _Service(config)
            seen = {}

            def fake_build(current):
                seen["paths"] = (
                    current.config.tls_certificate,
                    current.config.tls_private_key,
                    current.config.client_ca,
                )
                cert.write_bytes(b"certificate-attacker")
                seen["cert_bytes"] = current.config.tls_certificate.read_bytes()
                return "server"

            with patch.object(hardening, "_ORIGINAL_BUILD_WORKER_SERVER", fake_build):
                result = hardening._hardened_build_worker_server(service)

            self.assertEqual(result, "server")
            self.assertIs(service.config, config)
            self.assertEqual(seen["cert_bytes"], b"certificate-v1")
            self.assertNotEqual(seen["paths"][0], cert)
            self.assertTrue(all(not path.exists() for path in seen["paths"]))

    def test_server_builder_restores_config_when_ssl_setup_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key, ca = self._material_files(root)
            config = _ServerConfig(cert, key, ca)
            service = _Service(config)

            def fail_build(_service):
                raise RuntimeError("ssl setup failed")

            with patch.object(hardening, "_ORIGINAL_BUILD_WORKER_SERVER", fail_build):
                with self.assertRaisesRegex(RuntimeError, "ssl setup failed"):
                    hardening._hardened_build_worker_server(service)

            self.assertIs(service.config, config)

    def test_client_context_receives_only_snapshot_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key, ca = self._material_files(root)
            endpoint = _Endpoint(
                server_ca=ca,
                controller_certificate=cert,
                controller_private_key=key,
            )
            seen = {}

            def fake_context(current):
                seen["paths"] = (
                    current.server_ca,
                    current.controller_certificate,
                    current.controller_private_key,
                )
                key.write_bytes(b"private-key-attacker")
                seen["key_bytes"] = current.controller_private_key.read_bytes()
                return "context"

            with patch.object(hardening, "_ORIGINAL_CLIENT_CONTEXT", fake_context):
                result = hardening._hardened_client_context(endpoint)

            self.assertEqual(result, "context")
            self.assertEqual(seen["key_bytes"], b"private-key-v1")
            self.assertNotEqual(seen["paths"][2], key)
            self.assertTrue(all(not path.exists() for path in seen["paths"]))

    def test_snapshot_read_is_bounded_before_temp_material_is_created(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, _, _ = self._material_files(root)
            with patch.object(
                rw,
                "_read_direct_bytes",
                side_effect=rw.WorkerError("TLS material exceeds the configured read limit"),
            ):
                with self.assertRaisesRegex(rw.WorkerError, "read limit"):
                    with hardening._tls_material_snapshot(
                        rw,
                        {"server-cert.pem": (cert, "Worker TLS certificate")},
                    ):
                        self.fail("snapshot should not be yielded")


if __name__ == "__main__":
    unittest.main()
