import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.signing import generate_ed25519_keypair


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "public_auth_deployment_kit.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-public-auth-deployment-preflight.yml"
CONTRACT = ROOT / "ga-packs" / "04-public-auth" / "authority-contract.json"
STATUS = ROOT / "ga-packs" / "status.json"


class PublicAuthDeploymentKitTests(unittest.TestCase):
    COMMIT = "1" * 40
    RELEASE_DIGEST = "2" * 64
    WHEEL_DIGEST = "3" * 64
    VERSION = "2.0.0rc2"

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["SOURCE_DATE_EPOCH"] = "1775432100"
        return env

    def _build(
        self,
        root: Path,
        output: Path,
        private_key: Path,
        public_key: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "build",
                "--output",
                str(output),
                "--release-commit",
                self.COMMIT,
                "--version",
                self.VERSION,
                "--release-manifest-sha256",
                self.RELEASE_DIGEST,
                "--wheel-sha256",
                self.WHEEL_DIGEST,
                "--oauth-url",
                "https://oauth.example.com/mcp",
                "--mtls-url",
                "https://mtls.example.com/mcp",
                "--authorization-server",
                "https://identity.example.com",
                "--introspection-url",
                "https://identity.example.com/oauth2/introspect",
                "--required-scope",
                "psmatrix:mcp",
                "--rate-per-minute",
                "120",
                "--burst",
                "30",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
            ],
            cwd=root,
            env=self._env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _verify(
        self,
        root: Path,
        kit: Path,
        public_key: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "verify",
                str(kit),
                "--public-key",
                str(public_key),
                "--expected-release-commit",
                self.COMMIT,
                "--expected-version",
                self.VERSION,
                "--expected-release-manifest-sha256",
                self.RELEASE_DIGEST,
                "--expected-wheel-sha256",
                self.WHEEL_DIGEST,
            ],
            cwd=root,
            env=self._env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_two_builds_are_identical_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            first = root / "first.zip"
            second = root / "second.zip"

            first_build = self._build(root, first, private_key, public_key)
            second_build = self._build(root, second, private_key, public_key)
            self.assertEqual(first_build.returncode, 0, first_build.stderr)
            self.assertEqual(second_build.returncode, 0, second_build.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            verified = self._verify(root, first, public_key)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            value = json.loads(verified.stdout)
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["release_commit"], self.COMMIT)
            self.assertEqual(value["version"], self.VERSION)
            self.assertEqual(value["release_manifest_sha256"], self.RELEASE_DIGEST)
            self.assertEqual(value["wheel_sha256"], self.WHEEL_DIGEST)
            self.assertEqual(value["oauth_url"], "https://oauth.example.com/mcp")
            self.assertEqual(value["mtls_url"], "https://mtls.example.com/mcp")
            self.assertTrue(value["credential_free"])
            self.assertFalse(value["ga_eligible"])

    def test_tampered_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            original = root / "original.zip"
            tampered = root / "tampered.zip"
            completed = self._build(root, original, private_key, public_key)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as target:
                for info in source.infolist():
                    data = source.read(info)
                    if info.filename.endswith("config/oauth-http-auth.json"):
                        data = data.replace(b'"cache_seconds":30', b'"cache_seconds":31')
                    target.writestr(info, data)

            verified = self._verify(root, tampered, public_key)
            self.assertNotEqual(verified.returncode, 0)
            self.assertTrue(
                "digest/size mismatch" in verified.stderr
                or "attestation" in verified.stderr
                or "inventory" in verified.stderr,
                verified.stderr,
            )

    def test_same_hostname_or_different_public_ports_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            base = [
                sys.executable,
                str(SCRIPT),
                "build",
                "--output",
                str(root / "invalid.zip"),
                "--release-commit",
                self.COMMIT,
                "--version",
                self.VERSION,
                "--release-manifest-sha256",
                self.RELEASE_DIGEST,
                "--wheel-sha256",
                self.WHEEL_DIGEST,
                "--authorization-server",
                "https://identity.example.com",
                "--introspection-url",
                "https://identity.example.com/introspect",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
            ]
            cases = (
                (
                    "same-host",
                    "https://same.example.com/mcp",
                    "https://same.example.com/mcp",
                    "distinct DNS hostnames",
                ),
                (
                    "different-port",
                    "https://oauth.example.com:443/mcp",
                    "https://mtls.example.com:8443/mcp",
                    "same public port",
                ),
            )
            for name, oauth, mtls, expected in cases:
                with self.subTest(name=name):
                    completed = subprocess.run(
                        [*base, "--oauth-url", oauth, "--mtls-url", mtls],
                        cwd=root,
                        env=self._env(),
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(expected, completed.stderr)

    def test_archive_contains_direct_mtls_and_hardened_service_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            kit = root / "kit.zip"
            completed = self._build(root, kit, private_key, public_key)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with zipfile.ZipFile(kit) as archive:
                mtls_service = archive.read(
                    "psmatrix-public-auth/deploy/systemd/psmatrix-mtls.service"
                ).decode("utf-8")
                router = archive.read(
                    "psmatrix-public-auth/deploy/nginx/stream-public-auth.conf"
                ).decode("utf-8")
                oauth_config = json.loads(
                    archive.read("psmatrix-public-auth/config/oauth-http-auth.json")
                )
                mtls_config = json.loads(
                    archive.read("psmatrix-public-auth/config/mtls-http-auth.json")
                )
            for value in (
                "--tls-cert /etc/psmatrix/tls/mtls-server.pem",
                "--tls-key /etc/psmatrix/tls/mtls-server-key.pem",
                "--client-ca /etc/psmatrix/tls/client-ca-active.pem",
                "NoNewPrivileges=true",
                "ProtectSystem=strict",
                "PrivateDevices=true",
            ):
                self.assertIn(value, mtls_service)
            self.assertIn("ssl_preread on;", router)
            self.assertIn("oauth.example.com 127.0.0.1:9443", router)
            self.assertIn("mtls.example.com 127.0.0.1:8766", router)
            self.assertEqual(oauth_config["mode"], "oauth-introspection")
            self.assertEqual(oauth_config["audience"], "https://oauth.example.com/mcp")
            self.assertEqual(mtls_config["mode"], "mtls")
            self.assertEqual(mtls_config["resource_url"], "https://mtls.example.com/mcp")

    def test_workflow_builds_twice_verifies_and_removes_private_key(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-public-auth-deployment-preflight",
            "environment: production-ga-public-auth",
            "SOURCE_DATE_EPOCH",
            "deployment-kit-first.zip",
            "deployment-kit-second.zip",
            "public_auth_deployment_kit.py verify",
            "Remove deployment private key before verification",
            "shred -u -z -n 1 \"$private\"",
            '"status": "PASS_PARTIAL"',
            '"ga_eligible": False',
            "if: always()",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertLess(
            text.index("Remove deployment private key before verification"),
            text.index("Verify both deployment kits and exact release binding"),
        )

    def test_contract_and_status_include_deployment_preflight(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        deployment = contract["deployment_preflight"]
        self.assertEqual(
            deployment["workflow"],
            "production-ga-public-auth-deployment-preflight",
        )
        self.assertTrue(deployment["double_build_reproducibility_required"])
        self.assertTrue(deployment["signed_deployment_attestation_required"])
        self.assertTrue(deployment["credential_free_archive_required"])
        self.assertFalse(deployment["ga_eligible"])

        status = json.loads(STATUS.read_text(encoding="utf-8"))
        pack = next(row for row in status["packs"] if row["id"] == "04-public-auth")
        self.assertEqual(
            pack["deployment_preflight"]["workflow"],
            "production-ga-public-auth-deployment-preflight",
        )
        self.assertFalse(pack["deployment_preflight"]["ga_eligible"])


if __name__ == "__main__":
    unittest.main()
