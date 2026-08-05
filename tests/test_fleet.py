import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from psmatrix.fleet import FleetError, FleetRegistry
from psmatrix.signing import TrustStore, generate_ed25519_keypair


def run(args, cwd):
    subprocess.run(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def certificates(root: Path):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=Fleet CA"], root)
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost"], root)
    (root / "server.ext").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
    run(["openssl", "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext"], root)
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/CN=controller-a"], root)
    run(["openssl", "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "1"], root)


class FleetTests(unittest.TestCase):
    def _endpoint(self, root: Path, home: Path) -> Path:
        certificates(root)
        cpriv, cpub = root / "controller-sign.pem", root / "controller-sign.pub"
        wpriv, wpub = root / "worker-sign.pem", root / "worker-sign.pub"
        generate_ed25519_keypair(cpriv, cpub)
        generate_ed25519_keypair(wpriv, wpub)
        TrustStore(home).add("worker-a", "worker", wpub, certificate=root / "server.pem")
        endpoint = root / "endpoint.json"
        endpoint.write_text(json.dumps({
            "schema": 1,
            "url": "https://localhost:9443",
            "worker_id": "worker-a",
            "runtime_id": "windows-powershell-5.1",
            "controller_id": "controller-a",
            "tls": {
                "certificate": "client.pem", "private_key": "client.key", "server_ca": "ca.pem"
            },
            "controller_signing": {"private_key": "controller-sign.pem", "public_key": "controller-sign.pub"},
            "worker_signing": {"identity": "worker-a"}
        }), encoding="utf-8")
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
            fleet.record_health("worker-a", passed=True, capabilities={
                "runtime_id": "windows-powershell-5.1", "authoritative": True
            })
            selected = fleet.select("windows-powershell-5.1", labels={"zone": "lab-a"})
            self.assertEqual([item.worker_id for item in selected], ["worker-a"])
            fleet.record_health("worker-a", passed=False, error="down", quarantine_threshold=2)
            state = fleet.record_health("worker-a", passed=False, error="down", quarantine_threshold=2)
            self.assertEqual(state["state"], "QUARANTINED")
            self.assertEqual(fleet.select("windows-powershell-5.1", require_healthy=False), [])
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
