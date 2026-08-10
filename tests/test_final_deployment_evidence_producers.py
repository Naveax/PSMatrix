import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.ga import default_ga_policy
from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-deployment-evidence-producer-contract.json"
EVALUATOR_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
PROBE = ROOT / "scripts" / "ga" / "probe_final_public_auth.py"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-public-auth-live-probe.yml"
OAUTH_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-public-oauth.yml"
MTLS_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-public-mtls.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-deployment-evidence-producers-source-preflight.yml"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
CI_ANCHOR = "89866c0e7eaf0aa10c25fdbbc900e2f5bdaea97e"


def _load_probe():
    spec = importlib.util.spec_from_file_location("psmatrix_public_auth_probe_test", PROBE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalDeploymentEvidenceProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.evaluator = json.loads(EVALUATOR_CONTRACT.read_text(encoding="utf-8"))
        cls.probe = _load_probe()

    def test_contract_freezes_shared_live_probe_and_two_deployment_producers(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-deployment-evidence-producer-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["final_release_commit"], FINAL_COMMIT)
        self.assertEqual(value["ci_producer_anchor"], CI_ANCHOR)
        live = value["shared_live_probe"]
        self.assertEqual(live["workflow"], "production-ga-final-public-auth-live-probe")
        self.assertEqual(live["artifact"], "psmatrix-2.0.0-final-public-auth-live-report")
        self.assertEqual(live["environment"], "production-ga-public-auth-probe")
        self.assertEqual(live["runner"], "ubuntu-latest")
        self.assertEqual(live["max_rate_limit_attempts"], 32)
        self.assertTrue(live["public_dns_required"])
        self.assertTrue(live["globally_routable_addresses_required"])
        self.assertTrue(live["system_server_tls_trust_required"])
        self.assertTrue(live["separate_oauth_and_mtls_endpoints_required"])
        self.assertFalse(live["private_probe_material_allowed_in_artifact"])
        self.assertEqual(len(live["oauth_token_secrets"]), 6)
        self.assertEqual(len(live["mtls_keypair_secrets"]), 8)
        self.assertEqual(value["oauth"]["workflow"], "production-ga-final-public-oauth")
        self.assertEqual(value["mtls"]["workflow"], "production-ga-final-public-mtls")
        cross = value["cross_gate"]
        self.assertTrue(cross["same_live_report_sha256_required"])
        self.assertTrue(cross["different_public_endpoints_required"])
        self.assertTrue(cross["same_deployment_authority_required"])
        self.assertTrue(cross["same_release_commit_required"])
        self.assertTrue(cross["same_release_manifest_sha256_required"])
        self.assertTrue(cross["same_release_wheel_sha256_required"])
        authority = value["deployment_authority"]
        self.assertEqual(authority["environment"], "production-ga-deployment-signing")
        self.assertEqual(authority["private_key_secret"], "PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY")
        self.assertEqual(authority["public_key_secret"], "PSMATRIX_GA_DEPLOYMENT_PUBLIC_KEY")
        self.assertFalse(authority["private_key_allowed_in_live_probe"])
        self.assertTrue(authority["oauth_and_mtls_must_share_exact_authority"])

    def test_evaluator_contract_matches_oauth_mtls_workflows_and_runtime_deployment_authority(self) -> None:
        policy = default_ga_policy()
        expected = {
            "public-oauth": self.contract["oauth"],
            "public-mtls": self.contract["mtls"],
        }
        for gate, producer in expected.items():
            with self.subTest(gate=gate):
                evaluator = self.evaluator["evidence_sources"][gate]
                self.assertEqual(evaluator["workflow"], producer["workflow"])
                self.assertEqual(evaluator["workflow_path"], producer["workflow_path"])
                self.assertEqual(evaluator["artifact"], producer["artifact"])
                self.assertEqual(evaluator["authority"], "deployment")
                self.assertEqual(policy["evidence"][gate]["authority"], "deployment")

    def test_public_endpoint_validator_rejects_local_and_private_addresses(self) -> None:
        for value in (
            "http://example.com/auth",
            "https://localhost/auth",
            "https://127.0.0.1/auth",
            "https://10.1.2.3/auth",
            "https://192.168.1.1/auth",
            "https://user:pass@example.com/auth",
        ):
            with self.subTest(value=value), self.assertRaises(self.probe.PublicAuthProbeError):
                self.probe._validate_public_endpoint(value, "test endpoint")
        host, port, path = self.probe._validate_public_endpoint("https://8.8.8.8:443/auth", "test endpoint")
        self.assertEqual(host, "8.8.8.8")
        self.assertEqual(port, 443)
        self.assertEqual(path, "/auth")

    def test_shared_live_report_builds_two_exact_cross_bound_proof_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-proof-") as temp:
            root = Path(temp)
            report_path = root / "public-auth-live-report.json"
            release_manifest_sha = "a" * 64
            release_wheel_sha = "b" * 64
            report = {
                "schema": 1,
                "kind": "psmatrix.public-auth-live-report",
                "status": "PASS",
                "observed_at": "2026-08-10T12:00:00+00:00",
                "release_signing_run_id": "123456",
                "release": {
                    "version": "2.0.0",
                    "commit": FINAL_COMMIT,
                    "manifest_sha256": release_manifest_sha,
                    "wheel_name": "psmatrix-2.0.0-py3-none-any.whl",
                    "wheel_sha256": release_wheel_sha,
                    "release_public_key_sha256": "c" * 64,
                },
                "oauth": {
                    "endpoint": "https://oauth.example.com/mcp",
                    "resolved_addresses": ["8.8.8.8"],
                    "server_certificate_sha256": "d" * 64,
                    "external_probe": True,
                    "public_dns": True,
                    "public_tls": True,
                    "oauth_external": True,
                    "discovery_verified": True,
                    "audience_verified": True,
                    "scope_verified": True,
                    "token_expiry_verified": True,
                    "missing_token_rejected": True,
                    "wrong_audience_rejected": True,
                    "missing_scope_rejected": True,
                    "replay_protection_verified": True,
                    "rate_limiting_verified": True,
                },
                "mtls": {
                    "endpoint": "https://mtls.example.com/mcp",
                    "resolved_addresses": ["1.1.1.1"],
                    "server_certificate_sha256": "e" * 64,
                    "external_probe": True,
                    "public_dns": True,
                    "public_tls": True,
                    "client_certificate_required": True,
                    "untrusted_client_rejected": True,
                    "certificate_rotation_ready": True,
                    "revoked_client_rejected": True,
                    "tls_passthrough_verified": True,
                },
                "secrets_in_report": False,
                "private_keys_in_report": False,
            }
            report_path.write_text(json.dumps(report), encoding="utf-8")
            oauth_path = root / "oauth.json"
            mtls_path = root / "mtls.json"
            oauth = self.probe.build_proof_result(report_path=report_path, proof_type="public-oauth", output=oauth_path)
            mtls = self.probe.build_proof_result(report_path=report_path, proof_type="public-mtls", output=mtls_path)
            live_sha = sha256_file(report_path)
            self.assertEqual(oauth["artifacts"], [{"name": "public-auth-live-report.json", "sha256": live_sha}])
            self.assertEqual(mtls["artifacts"], [{"name": "public-auth-live-report.json", "sha256": live_sha}])
            self.assertNotEqual(oauth["assertions"]["endpoint"], mtls["assertions"]["endpoint"])
            for key, expected in (
                ("release_commit", FINAL_COMMIT),
                ("release_manifest_sha256", release_manifest_sha),
                ("release_wheel_sha256", release_wheel_sha),
                ("expected_version", "2.0.0"),
            ):
                self.assertEqual(oauth["assertions"][key], expected)
                self.assertEqual(mtls["assertions"][key], expected)

    def test_probe_source_is_bounded_and_never_serializes_probe_secrets(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        required = (
            "_MAX_BODY = 64 * 1024",
            "timeout > 30",
            "attempts > 32",
            "address.is_global",
            "ssl.create_default_context()",
            "OAuth and mTLS public endpoints must be different",
            "OAuth replay protection did not accept once and reject the replay",
            "OAuth rate limiting did not return HTTP 429",
            "mTLS endpoint did not echo the exact current client certificate SHA-256",
            '"secrets_in_report": False',
            '"private_keys_in_report": False',
            '"artifacts": [{"name": "public-auth-live-report.json", "sha256": live_sha}]',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            '"Authorization": f"Bearer {bearer}"',
            '"token": valid_token',
            '"private_key":',
            "requests.",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_live_probe_workflow_keeps_deployment_key_out_and_probe_secrets_in_one_step(self) -> None:
        text = LIVE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-final-public-auth-live-probe",
            "runs-on: ubuntu-latest",
            "environment: production-ga-public-auth-probe",
            "production-ga-windows-authority-final-release-sign-from-lock",
            "psmatrix-2.0.0-protected-release",
            "Materialize bounded probe credentials, execute live probe, and remove secrets",
            "PSMATRIX_OAUTH_VALID_TOKEN",
            "PSMATRIX_OAUTH_REPLAY_TOKEN",
            "PSMATRIX_OAUTH_RATE_LIMIT_TOKEN",
            "PSMATRIX_MTLS_CURRENT_KEY",
            "PSMATRIX_MTLS_ROTATION_KEY",
            "PSMATRIX_MTLS_UNTRUSTED_KEY",
            "PSMATRIX_MTLS_REVOKED_KEY",
            "public_auth_live_report=PASS secret_material_absent=true",
            "psmatrix-2.0.0-final-public-auth-live-report",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertNotIn("PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY", text)
        self.assertNotIn("PSMATRIX_GA_DEPLOYMENT_PUBLIC_KEY", text)
        self.assertEqual(text.count("secrets.PSMATRIX_OAUTH_VALID_TOKEN"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_MTLS_CURRENT_KEY"), 1)

    def test_oauth_and_mtls_workflows_share_deployment_authority_and_validate_live_report_before_secret(self) -> None:
        oauth = OAUTH_WORKFLOW.read_text(encoding="utf-8")
        mtls = MTLS_WORKFLOW.read_text(encoding="utf-8")
        for proof_type, text, workflow, artifact in (
            ("public-oauth", oauth, "production-ga-final-public-oauth", "psmatrix-2.0.0-final-public-oauth"),
            ("public-mtls", mtls, "production-ga-final-public-mtls", "psmatrix-2.0.0-final-public-mtls"),
        ):
            with self.subTest(proof_type=proof_type):
                self.assertIn(f"name: {workflow}", text)
                self.assertIn("environment: production-ga-deployment-signing", text)
                self.assertIn("production-ga-final-public-auth-live-probe", text)
                self.assertIn("psmatrix-2.0.0-final-public-auth-live-report", text)
                self.assertIn("live report final-signing run is not a successful exact-head run", text)
                self.assertIn(f"--type {proof_type}", text)
                self.assertIn("PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY", text)
                self.assertIn("PSMATRIX_GA_DEPLOYMENT_PUBLIC_KEY", text)
                self.assertIn("ga proof-create", text)
                self.assertIn("ga proof-verify", text)
                self.assertIn(artifact, text)
                self.assertEqual(text.count("secrets.PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY"), 1)
                pre_secret = text.index("Validate live report and frozen final-signing provenance before deployment-key access")
                secret = text.index("Materialize deployment authority")
                self.assertLess(pre_secret, secret)

    def test_source_preflight_reports_six_of_eleven_producers_after_this_layer(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-deployment-evidence-producers-source-preflight",
            "final-deployment-evidence-producer-contract.json",
            "ga-final-public-auth-live-probe.yml",
            "ga-final-public-oauth.yml",
            "ga-final-public-mtls.yml",
            "probe_final_public_auth.py",
            "tests.test_final_deployment_evidence_producers",
            "deployment_producer_control_changed_paths=7",
            "runtime_source_changes=0",
            "evaluator_producer_sources_present=6",
            "evaluator_producer_sources_required=11",
            "live_probe_executed=false",
            "oauth_producer_executed=false",
            "mtls_producer_executed=false",
            "deployment_private_key_read=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
