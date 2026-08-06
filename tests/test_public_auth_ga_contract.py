import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "ga" / "probe_public_auth.py"
BINDER = ROOT / "scripts" / "ga" / "bind_public_auth_release.py"
ENFORCER = ROOT / "scripts" / "ga" / "enforce_public_auth_report.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-public-auth-external.yml"
CONTRACT = ROOT / "ga-packs" / "04-public-auth" / "authority-contract.json"
STATUS = ROOT / "ga-packs" / "status.json"
GA_SOURCE = ROOT / "src" / "psmatrix" / "ga.py"


COMMIT = "1" * 40
VERSION = "2.0.0rc2"
MANIFEST_DIGEST = "2" * 64
WHEEL_DIGEST = "3" * 64

_REQUIRED_OAUTH_ASSERTIONS = (
    "external_probe",
    "public_dns",
    "public_tls",
    "oauth_external",
    "discovery_verified",
    "audience_verified",
    "scope_verified",
    "token_expiry_verified",
    "missing_token_rejected",
    "wrong_audience_rejected",
    "missing_scope_rejected",
    "replay_protection_verified",
    "rate_limiting_verified",
    "release_commit_bound",
)
_REQUIRED_MTLS_ASSERTIONS = (
    "external_probe",
    "public_dns",
    "public_tls",
    "client_certificate_required",
    "untrusted_client_rejected",
    "certificate_rotation_ready",
    "revoked_client_rejected",
    "tls_passthrough_verified",
    "release_commit_bound",
)


class PublicAuthGAContractTests(unittest.TestCase):
    def _write(self, path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _checks(self) -> list[dict]:
        rows = []

        def add(group: str, name: str, detail=True) -> None:
            rows.append({"group": group, "name": name, "status": "PASS", "detail": detail})

        for name in (
            "public-dns",
            "public-trusted-tls",
            "health-version",
            "protected-resource-discovery",
            "valid-token-accepted",
        ):
            add("oauth", name)
        for name in (
            "missing-token-rejected",
            "wrong-audience-rejected",
            "expired-token-rejected",
            "missing-scope-rejected",
        ):
            add("oauth", name, "HTTP_401")
        add(
            "oauth",
            "request-replay-protection",
            {
                "exact_duplicate_cached": True,
                "different_content_rejected": True,
                "collision_status": 400,
            },
        )
        add("oauth", "rate-limiting", {"triggered": True, "request_number": 31})

        for name in ("public-dns", "public-trusted-tls", "health-version"):
            add("mtls", name)
        for name in (
            "missing-client-certificate-rejected",
            "untrusted-client-certificate-rejected",
            "revoked-client-certificate-rejected",
        ):
            add("mtls", name, "TLS_OR_TRANSPORT_REJECTED:ProbeError")
        for name in ("valid-client-certificate-accepted", "rotated-client-certificate-accepted"):
            add(
                "mtls",
                name,
                {"status": 200, "session_created": True, "server_identity": "PSMatrixHTTP"},
            )
        return rows

    def _proof(self, proof_type: str) -> dict:
        oauth = proof_type == "public-oauth"
        keys = _REQUIRED_OAUTH_ASSERTIONS if oauth else _REQUIRED_MTLS_ASSERTIONS
        assertions = {key: True for key in keys}
        assertions.update(
            {
                "endpoint": "https://oauth.example.com/mcp" if oauth else "https://mtls.example.com/mcp",
                "resolved_addresses": ["93.184.216.34"],
                "release_commit": COMMIT,
                "expected_version": VERSION,
                "server_certificate_sha256": ("4" if oauth else "5") * 64,
            }
        )
        return {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": proof_type,
            "status": "PASS",
            "observed_at": "2026-08-06T00:00:00+00:00",
            "release_commit": COMMIT,
            "artifacts": [{"name": "public-auth-live-report.json", "sha256": "a" * 64}],
            "assertions": assertions,
        }

    def _report(self, checks: list[dict] | None = None) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.public-auth-live-report",
            "release_commit": COMMIT,
            "expected_version": VERSION,
            "external_probe": True,
            "oauth": {"status": "PASS"},
            "mtls": {"status": "PASS"},
            "checks": checks or self._checks(),
        }

    def _prepare(self, root: Path, report: dict) -> tuple[Path, Path, Path]:
        report_path = root / "public-auth-live-report.json"
        oauth_path = root / "public-oauth-proof-input.json"
        mtls_path = root / "public-mtls-proof-input.json"
        self._write(report_path, report)
        self._write(oauth_path, self._proof("public-oauth"))
        self._write(mtls_path, self._proof("public-mtls"))
        return report_path, oauth_path, mtls_path

    def _bind(self, root: Path, report: dict) -> tuple[subprocess.CompletedProcess[str], tuple[Path, Path, Path]]:
        paths = self._prepare(root, report)
        report_path, oauth_path, mtls_path = paths
        completed = subprocess.run(
            [
                sys.executable,
                str(BINDER),
                "--report",
                str(report_path),
                "--oauth-proof",
                str(oauth_path),
                "--mtls-proof",
                str(mtls_path),
                "--release-commit",
                COMMIT,
                "--expected-version",
                VERSION,
                "--release-manifest-sha256",
                MANIFEST_DIGEST,
                "--release-wheel-sha256",
                WHEEL_DIGEST,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed, paths

    def _enforce(self, paths: tuple[Path, Path, Path]) -> subprocess.CompletedProcess[str]:
        report_path, oauth_path, mtls_path = paths
        return subprocess.run(
            [
                sys.executable,
                str(ENFORCER),
                "--report",
                str(report_path),
                "--oauth-proof",
                str(oauth_path),
                "--mtls-proof",
                str(mtls_path),
                "--release-commit",
                COMMIT,
                "--expected-version",
                VERSION,
                "--release-manifest-sha256",
                MANIFEST_DIGEST,
                "--release-wheel-sha256",
                WHEEL_DIGEST,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_probe_binder_and_enforcer_are_valid_python(self) -> None:
        for path in (PROBE, BINDER, ENFORCER):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_release_binding_then_exact_semantic_enforcement_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bound, paths = self._bind(Path(temp), self._report())
            self.assertEqual(bound.returncode, 0, bound.stderr)
            completed = self._enforce(paths)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["release_manifest_sha256"], MANIFEST_DIGEST)
        self.assertEqual(value["release_wheel_sha256"], WHEEL_DIGEST)
        self.assertTrue(value["release_bound"])
        self.assertTrue(value["safe_to_sign"])

    def test_http_500_cannot_satisfy_oauth_negative_control(self) -> None:
        checks = self._checks()
        target = next(row for row in checks if row["group"] == "oauth" and row["name"] == "wrong-audience-rejected")
        target["detail"] = "HTTP_500"
        with tempfile.TemporaryDirectory() as temp:
            bound, paths = self._bind(Path(temp), self._report(checks))
            self.assertEqual(bound.returncode, 0, bound.stderr)
            completed = self._enforce(paths)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must reject with HTTP 401", completed.stderr)

    def test_tampered_live_report_after_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bound, paths = self._bind(root, self._report())
            self.assertEqual(bound.returncode, 0, bound.stderr)
            report_path = paths[0]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["summary"] = {"tampered": True}
            self._write(report_path, report)
            completed = self._enforce(paths)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("live-report digest does not match", completed.stderr)

    def test_wrong_release_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bound, paths = self._bind(Path(temp), self._report())
            self.assertEqual(bound.returncode, 0, bound.stderr)
            report_path, oauth_path, mtls_path = paths
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ENFORCER),
                    "--report",
                    str(report_path),
                    "--oauth-proof",
                    str(oauth_path),
                    "--mtls-proof",
                    str(mtls_path),
                    "--release-commit",
                    COMMIT,
                    "--expected-version",
                    VERSION,
                    "--release-manifest-sha256",
                    "f" * 64,
                    "--release-wheel-sha256",
                    WHEEL_DIGEST,
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release-manifest binding mismatch", completed.stderr)

    def test_workflow_uses_release_binder_external_authority_and_exact_cli_syntax(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-public-auth-external",
            "runs-on: ubuntu-latest",
            "environment: production-ga-public-auth",
            "release_manifest_sha256:",
            "wheel_sha256:",
            "RUNNER_ENVIRONMENT",
            "probe_public_auth.py",
            "bind_public_auth_release.py",
            "enforce_public_auth_report.py",
            "--release-manifest-sha256 \"$PSMATRIX_PUBLIC_AUTH_RELEASE_MANIFEST_SHA256\"",
            "--release-wheel-sha256 \"$PSMATRIX_PUBLIC_AUTH_WHEEL_SHA256\"",
            "--attestation \"$output/public-oauth.dsse.json\"",
            "--attestation \"$output/public-mtls.dsse.json\"",
            "if: always()",
            "if-no-files-found: error",
            "shred -u -z -n 1",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertEqual(text.count("--attestation \"$output/public-"), 2)
        self.assertLess(
            text.index("Bind live proof to exact signed release artifacts"),
            text.index("Enforce exact rejection and release-binding semantics"),
        )
        self.assertLess(
            text.index("Enforce exact rejection and release-binding semantics"),
            text.index("Sign and verify external authority proofs"),
        )
        self.assertIn("stdout_log=\"$RUNNER_TEMP/psmatrix-public-auth-probe.stdout.log\"", text)
        self.assertNotIn("tee \"$output/probe.stdout.log\"", text)

    def test_workflow_never_passes_token_values_as_command_arguments(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("--valid-token ", text)
        self.assertNotIn("--wrong-audience-token ", text)
        self.assertNotIn("--expired-token ", text)
        self.assertIn("--valid-token-env", PROBE.read_text(encoding="utf-8"))
        for name in (
            "PSMATRIX_PUBLIC_AUTH_VALID_TOKEN",
            "PSMATRIX_PUBLIC_AUTH_WRONG_AUDIENCE_TOKEN",
            "PSMATRIX_PUBLIC_AUTH_EXPIRED_TOKEN",
            "PSMATRIX_PUBLIC_AUTH_MISSING_SCOPE_TOKEN",
            "PSMATRIX_PUBLIC_AUTH_RATE_TOKEN",
        ):
            self.assertIn(name, text)

    def test_authority_contract_and_machine_state_are_synchronized(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["authority"]["protected_environment"], "production-ga-public-auth")
        self.assertEqual(contract["authority"]["external_runner"], "github-hosted")
        self.assertTrue(contract["network"]["oauth_and_mtls_endpoints_must_differ"])
        self.assertTrue(contract["release_binding"]["exact_full_commit_required"])
        self.assertTrue(contract["release_binding"]["signed_release_manifest_sha256_required"])
        self.assertTrue(contract["release_binding"]["exact_release_wheel_sha256_required"])
        self.assertTrue(contract["release_binding"]["final_evaluator_cross_binding_required"])
        self.assertTrue(contract["oauth"]["five_distinct_tokens_required"])
        self.assertTrue(contract["mtls"]["four_distinct_client_certificates_required"])
        self.assertEqual(contract["completion"]["signed_proofs_required"], 2)
        self.assertFalse(contract["completion"]["ga_eligible"])

        status = json.loads(STATUS.read_text(encoding="utf-8"))
        pack = next(row for row in status["packs"] if row["id"] == "04-public-auth")
        self.assertEqual(
            pack["state"],
            "DEPLOYMENT_KIT_PREFLIGHT_READY_EXTERNAL_PROOF_DEPLOYMENT_PENDING",
        )
        self.assertFalse(pack["ga_eligible"])
        self.assertEqual(pack["external_workflow"]["workflow"], "production-ga-public-auth-external")
        self.assertTrue(pack["external_workflow"]["release_manifest_sha256_required"])
        self.assertTrue(pack["external_workflow"]["wheel_sha256_required"])
        self.assertTrue(pack["external_workflow"]["final_evaluator_cross_binding"])
        self.assertEqual(pack["authority_contract"], "ga-packs/04-public-auth/authority-contract.json")

    def test_ga_engine_cross_binds_both_public_proof_types(self) -> None:
        text = GA_SOURCE.read_text(encoding="utf-8")
        self.assertIn('"public-oauth"', text)
        self.assertIn('"public-mtls"', text)
        self.assertIn('proof_type == "public-oauth"', text)
        self.assertIn('proof_type == "public-mtls"', text)
        self.assertIn("_public_release_binding", text)
        self.assertIn("release_manifest_sha256", text)
        self.assertIn("release_wheel_sha256", text)
        self.assertIn("same live report", text)


if __name__ == "__main__":
    unittest.main()
