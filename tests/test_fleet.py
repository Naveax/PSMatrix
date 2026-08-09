import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from psmatrix.fleet import FleetError, FleetRegistry
from psmatrix.signing import TrustStore, generate_ed25519_keypair


def run(args: list[str], cwd: Path) -> None:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "OpenSSL fixture command failed "
            f"({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout[-4096:]}\n"
            f"stderr:\n{completed.stderr[-4096:]}"
        )


def certificates(root: Path) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise unittest.SkipTest("OpenSSL is required for the fleet TLS integration fixture")

    (root / "ca.cnf").write_text(
        """[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
CN = Fleet CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
""",
        encoding="utf-8",
    )
    run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-config",
            "ca.cnf",
        ],
        root,
    )

    (root / "server.cnf").write_text(
        """[req]
prompt = no
distinguished_name = dn

[dn]
CN = localhost
""",
        encoding="utf-8",
    )
    (root / "server.ext").write_text(
        """[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
""",
        encoding="utf-8",
    )
    run(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-config",
            "server.cnf",
        ],
        root,
    )
    run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "server.ext",
            "-extensions",
            "v3_server",
        ],
        root,
    )

    (root / "client.cnf").write_text(
        """[req]
prompt = no
distinguished_name = dn

[dn]
CN = controller-a
""",
        encoding="utf-8",
    )
    (root / "client.ext").write_text(
        """[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
""",
        encoding="utf-8",
    )
    run(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "client.key",
            "-out",
            "client.csr",
            "-config",
            "client.cnf",
        ],
        root,
    )
    run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            "client.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "client.pem",
            "-days",
            "1",
            "-extfile",
            "client.ext",
            "-extensions",
            "v3_client",
        ],
        root,
    )


class FleetTests(unittest.TestCase):
    def _endpoint(self, root: Path, home: Path) -> Path:
        certificates(root)
        cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
        wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
        generate_ed25519_keypair(cpriv, cpub)
        generate_ed25519_keypair(wpriv, wpub)
        TrustStore(home).add("worker-a", "worker", wpub, certificate=root / "server.pem")
        endpoint = root / "endpoint.json"
        endpoint.write_text(
            json.dumps({
                "schema": 1,
                "url": "https://localhost:9443",
                "worker_id": "worker-a",
                "runtime_id": "windows-powershell-5.1",
                "controller_id": "controller-a",
                "tls": {
                    "certificate": "client.pem",
                    "private_key": "client.key",
                    "server_ca": "ca.pem",
                },
                "controller_signing": {
                    "private_key": "controller-sign.pem",
                    "public_key": "controller-sign.pub",
                },
                "worker_signing": {"identity": "worker-a"},
            }),
            encoding="utf-8",
        )
        return endpoint

    def test_enroll_health_quarantine_selection_and_revocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            endpoint = self._endpoint(root, home)
            fleet = FleetRegistry(home)
            enrolled = fleet.enroll(endpoint, labels={"zone": "lab-a"}, priority=200)
            self.assertEqual(enrolled["state"], "ACTIVE")
            self.assertEqual(fleet.select("windows-powershell-5.1"), [])
            fleet.record_health(
                "worker-a",
                passed=True,
                capabilities={
                    "runtime_id": "windows-powershell-5.1",
                    "authoritative": True,
                },
            )
            selected = fleet.select(
                "windows-powershell-5.1",
                labels={"zone": "lab-a"},
            )
            self.assertEqual([item.worker_id for item in selected], ["worker-a"])
            fleet.record_health(
                "worker-a",
                passed=False,
                error="down",
                quarantine_threshold=2,
            )
            state = fleet.record_health(
                "worker-a",
                passed=False,
                error="down",
                quarantine_threshold=2,
            )
            self.assertEqual(state["state"], "QUARANTINED")
            self.assertEqual(
                fleet.select("windows-powershell-5.1", require_healthy=False),
                [],
            )
            fleet.transition("worker-a", "ACTIVE", reason="manual recovery")
            fleet.transition("worker-a", "REVOKED", reason="retired")
            with self.assertRaises(FleetError):
                fleet.transition("worker-a", "ACTIVE", reason="not allowed")

    def test_registry_integrity_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            endpoint = self._endpoint(root, home)
            fleet = FleetRegistry(home)
            fleet.enroll(endpoint)
            registry_path = home / "fleet" / "registry.json"
            value = json.loads(registry_path.read_text(encoding="utf-8"))
            value["workers"][0]["state"] = "QUARANTINED"
            registry_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(FleetError):
                fleet.list()


if __name__ == "__main__":
    unittest.main()
