import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "ga" / "probe_public_auth.py"
ENFORCER = ROOT / "scripts" / "ga" / "enforce_public_auth_report.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-public-auth-external.yml"
CONTRACT = ROOT / "ga-packs" / "04-public-auth" / "authority-contract.json"
STATUS = ROOT / "ga-packs" / "status.json"
GA_SOURCE = ROOT / "src" / "psmatrix" / "ga.py"


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

    def _proof(self, proof_type: str, commit: str) -> dict:
        keys = _REQUIRED_OAUTH_ASSERTIONS if proof_type == "public-oauth" else _REQUIRED_MTLS_ASSERTIONS
        assertions = {key: True for key in keys}
        assertions.update(
            {
                "endpoint": "https://example.com/mcp",
                "resolved_addresses": ["203.0.113.10"],
                "release_commit": commit,
            }
        )
        return {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": proof_type,
            "status": "PASS",
            "observed_at": "2026-08-06T00:00:00+00:00",
            "release_commit": commit,
            "artifacts": [{"name": "public-auth-live-report.json", "sha256": "a" * 64}],
            "assertions": assertions,
        }

    def _run_enforcer(self, root: Path, report: dict) -> subprocess.CompletedProcess[str]:
        commit = "1" * 40
        report_path = root / "report.json"
        oauth_path = root / "oauth.json"
        mtls_path = root / "mtls.json"
        self._write(report_path, report)
        self._write(oauth_path, self._proof("public-oauth", commit))
        self._write(mtls_path, self._proof("public-mtls", commit))
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
                commit,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_probe_and_enforcer_are_valid_python(self) -> None:
        ast.parse(PROBE.read_text(encoding="utf-8"), filename=str(PROBE))
        ast.parse(ENFORCER.read_text(encoding="utf-8"), filename=str(ENFORCER))

    def test_exact_negative_semantics_accept_valid_report(self) -> None:
        commit = "1" * 40
        report = {
            "schema": 1,
            "kind": "psmatrix.public-auth-live-report",
            "release_commit": commit,
            "external_probe": True,
            "oauth": {"status": "PASS"},
            "mtls": {"status": "PASS"},
            "checks": self._checks(),
        }
        with tempfile.TemporaryDirectory() as temp:
            completed = self._run_enforcer(Path(temp), report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertEqual(value["status"], "PASS")
        self.assertTrue(value["safe_to_sign"])

    def test_http_500_cannot_satisfy_oauth_negative_control(self) -> None:
        commit = "1" * 40
        checks = self._checks()
        target = next(row for row in checks if row["group"] == "oauth" and row["name"] == "wrong-audience-rejected")
        target["detail"] = "HTTP_500"
        report = {
            "schema": 1,
            "kind": "psmatrix.public-auth-live-report",
            "release_commit": commit,
            "external_probe": True,
            "oauth": {"status": "PASS"},
            "mtls": {"status": "PASS"},
            "checks": checks,
        }
        with tempfile.TemporaryDirectory() as temp:
            completed = self._run_enforcer(Path(temp), report)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must reject with HTTP 401", completed.stderr)

    def test_workflow_uses_external_protected_authority_and_exact_cli_syntax(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-public-auth-external",
            "runs-on: ubuntu-latest",
            "environment: production-ga-public-auth",
            "RUNNER_ENVIRONMENT",
            "probe_public_auth.py",
            "enforce_public_auth_report.py",
            "--attestation \"$output/public-oauth.dsse.json\"",
            "--attestation \"$output/public-mtls.dsse.json\"",
            "if: always()",
            "if-no-files-found: error",
            "shred -u -z -n 1",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn("python -m psmatrix ga proof-verify \\\n            \"$output/", text)
        self.assertIn("stdout_log=\"$RUNNER_TEMP/psmatrix-public-auth-probe.stdout.log\"", text)
        self.assertNotIn("tee \"$output/probe.stdout.log\"", text)

    def test_workflow_never_passes_token_values_as_command_arguments(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("--valid-token", text)
        self.assertNotIn("--wrong-audience-token", text)
        self.assertNotIn("--expired-token", text)
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
        self.assertTrue(contract["oauth"]["five_distinct_tokens_required"])
        self.assertTrue(contract["mtls"]["four_distinct_client_certificates_required"])
        self.assertEqual(contract["completion"]["signed_proofs_required"], 2)
        self.assertFalse(contract["completion"]["ga_eligible"])

        status = json.loads(STATUS.read_text(encoding="utf-8"))
        pack = next(row for row in status["packs"] if row["id"] == "04-public-auth")
        self.assertEqual(pack["state"], "EXTERNAL_PROOF_WORKFLOW_READY_DEPLOYMENT_PENDING")
        self.assertFalse(pack["ga_eligible"])
        self.assertEqual(pack["external_workflow"]["workflow"], "production-ga-public-auth-external")
        self.assertEqual(pack["authority_contract"], "ga-packs/04-public-auth/authority-contract.json")

    def test_ga_engine_supports_both_signed_proof_types(self) -> None:
        text = GA_SOURCE.read_text(encoding="utf-8")
        self.assertIn('"public-oauth"', text)
        self.assertIn('"public-mtls"', text)
        self.assertIn('proof_type == "public-oauth"', text)
        self.assertIn('proof_type == "public-mtls"', text)


if __name__ == "__main__":
    unittest.main()
