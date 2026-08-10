import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.ga import default_ga_policy, run_key_rotation_drill, verify_ga_proof
from psmatrix.signing import generate_ed25519_keypair, public_key_id
from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-operations-release-evidence-producer-contract.json"
EVALUATOR = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
OTLP_PROBE = ROOT / "scripts" / "ga" / "probe_final_external_otlp.py"
OTLP_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-external-otlp.yml"
ROTATION_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-key-rotation.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-operations-release-evidence-producers-source-preflight.yml"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
DEPLOYMENT_ANCHOR = "2dcf33a91c118b62f0aa4364bccdbb13bc89942c"


def _load_probe():
    spec = importlib.util.spec_from_file_location("psmatrix_final_external_otlp_probe_test", OTLP_PROBE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _otlp_report() -> dict:
    return {
        "schema": 1,
        "kind": "psmatrix.external-otlp-live-report",
        "status": "PASS",
        "observed_at": "2026-08-10T11:30:00+00:00",
        "release_signing_run_id": "123456",
        "release": {
            "version": "2.0.0",
            "commit": FINAL_COMMIT,
            "manifest_sha256": "a" * 64,
            "wheel_name": "psmatrix-2.0.0-py3-none-any.whl",
            "wheel_sha256": "b" * 64,
            "release_public_key_sha256": "c" * 64,
        },
        "otlp": {
            "endpoint": "https://8.8.8.8/v1/metrics",
            "resolved_addresses": ["8.8.8.8"],
            "server_certificate_sha256": "d" * 64,
            "request_path": "/v1/metrics",
            "status_code": 202,
            "authenticated_status_codes": [202, 202],
            "unauthenticated_status_code": 401,
            "successful_exports": 2,
            "external_probe": True,
            "public_dns": True,
            "public_tls": True,
            "collector_external": True,
            "authenticated_tls": True,
            "unauthenticated_request_rejected": True,
        },
        "secrets_in_report": False,
        "private_keys_in_report": False,
        "metrics_payload_in_report": False,
        "absolute_paths_in_report": False,
    }


class FinalOperationsReleaseEvidenceProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.evaluator = json.loads(EVALUATOR.read_text(encoding="utf-8"))
        cls.probe = _load_probe()

    def test_contract_freezes_two_producers_and_authority_boundaries(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-operations-release-evidence-producer-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["final_release_commit"], FINAL_COMMIT)
        self.assertEqual(value["deployment_producer_anchor"], DEPLOYMENT_ANCHOR)
        otlp = value["external_otlp"]
        self.assertEqual(otlp["workflow"], "production-ga-final-external-otlp")
        self.assertEqual(otlp["artifact"], "psmatrix-2.0.0-final-external-otlp")
        self.assertEqual(otlp["authority"], "operations")
        self.assertEqual(otlp["probe_environment"], "production-ga-external-otlp-probe")
        self.assertEqual(otlp["signing_environment"], "production-ga-operations-signing")
        self.assertEqual(otlp["successful_exports_required"], 2)
        self.assertTrue(otlp["unauthenticated_rejection_required"])
        self.assertFalse(otlp["secret_values_allowed_in_artifact"])
        self.assertFalse(otlp["private_key_allowed_in_probe_job"])
        rotation = value["key_rotation"]
        self.assertEqual(rotation["workflow"], "production-ga-final-key-rotation")
        self.assertEqual(rotation["artifact"], "psmatrix-2.0.0-final-key-rotation")
        self.assertEqual(rotation["authority"], "release")
        self.assertEqual(rotation["signing_environment"], "production-ga-release-signing")
        self.assertEqual(rotation["private_signing_key_secret"], "PSMATRIX_RELEASE_PRIVATE_KEY")
        self.assertFalse(rotation["actual_release_authority_rotation_allowed"])
        self.assertTrue(rotation["bounded_temporary_trust_drill_required"])
        self.assertEqual(rotation["minimum_trust_generation"], 2)

    def test_evaluator_contract_and_runtime_policy_match_new_producers(self) -> None:
        policy = default_ga_policy()
        for gate, field, authority in (
            ("external-otlp", "external_otlp", "operations"),
            ("key-rotation", "key_rotation", "release"),
        ):
            with self.subTest(gate=gate):
                producer = self.contract[field]
                evaluator = self.evaluator["evidence_sources"][gate]
                self.assertEqual(evaluator["workflow"], producer["workflow"])
                self.assertEqual(evaluator["workflow_path"], producer["workflow_path"])
                self.assertEqual(evaluator["artifact"], producer["artifact"])
                self.assertEqual(evaluator["authority"], authority)
                self.assertEqual(policy["evidence"][gate]["authority"], authority)
        self.assertEqual(self.evaluator["authority_closure"]["release_must_match_across"], ["signed-release", "key-rotation"])

    def test_otlp_endpoint_normalization_is_public_https_only(self) -> None:
        for value in (
            "http://collector.example.com",
            "https://localhost/v1/metrics",
            "https://127.0.0.1/v1/metrics",
            "https://10.0.0.1/v1/metrics",
            "https://user:pass@collector.example.com/v1/metrics",
            "https://collector.example.com/v1/metrics?token=x",
        ):
            with self.subTest(value=value), self.assertRaises(self.probe.ExternalOTLPProbeError):
                normalized = self.probe._normalized_endpoint(value)
                if normalized:
                    self.probe._resolve_public(normalized)
        self.assertEqual(
            self.probe._normalized_endpoint("https://8.8.8.8/otel"),
            "https://8.8.8.8/otel/v1/metrics",
        )
        self.assertEqual(
            self.probe._normalized_endpoint("https://[2606:4700:4700::1111]/otel"),
            "https://[2606:4700:4700::1111]/otel/v1/metrics",
        )

    def test_otlp_live_report_builds_exact_ga_proof_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-proof-") as temp:
            root = Path(temp)
            report = root / "external-otlp-live-report.json"
            value = _otlp_report()
            report.write_text(json.dumps(value), encoding="utf-8")
            output = root / "external-otlp-result.json"
            result = self.probe.build_proof_result(report_path=report, output=output)
            self.assertEqual(result["proof_type"], "external-otlp")
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["artifacts"], [{"name": "external-otlp-live-report.json", "sha256": sha256_file(report)}])
            assertions = result["assertions"]
            for name in self.contract["external_otlp"]["required_assertions"]:
                self.assertIs(assertions[name], True)
            self.assertEqual(assertions["request_path"], "/v1/metrics")
            self.assertEqual(assertions["status_code"], 202)
            self.assertEqual(assertions["successful_exports"], 2)
            self.assertEqual(assertions["release_commit"], FINAL_COMMIT)

    def test_otlp_proof_result_rejects_tampered_transport_observations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-tamper-") as temp:
            root = Path(temp)
            report = root / "external-otlp-live-report.json"
            output = root / "result.json"
            for mutation in ("status", "unauth", "private-address", "bad-cert"):
                value = _otlp_report()
                if mutation == "status":
                    value["otlp"]["status_code"] = 500
                elif mutation == "unauth":
                    value["otlp"]["unauthenticated_status_code"] = 200
                elif mutation == "private-address":
                    value["otlp"]["resolved_addresses"] = ["127.0.0.1"]
                else:
                    value["otlp"]["server_certificate_sha256"] = "not-a-sha"
                report.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(mutation=mutation), self.assertRaises(self.probe.ExternalOTLPProbeError):
                    self.probe.build_proof_result(report_path=report, output=output)

    def test_otlp_report_scan_rejects_single_backslash_windows_and_posix_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-otlp-leak-") as temp:
            root = Path(temp)
            report = root / "report.json"
            for leaked in (r"C:\Users\navea\secret.txt", "/tmp/psmatrix-secret.txt"):
                report.write_text(json.dumps({"leak": leaked}), encoding="utf-8")
                with self.subTest(leaked=leaked), self.assertRaises(self.probe.ExternalOTLPProbeError):
                    self.probe._safe_report_scan(report, [])

    def test_key_rotation_runtime_drill_roundtrip_uses_supplied_release_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-key-rotation-") as temp:
            root = Path(temp)
            private = root / "release.private.pem"
            public = root / "release-public.pem"
            generate_ed25519_keypair(private, public)
            envelope = run_key_rotation_drill(signing_private_key=private, signing_public_key=public)
            verified = verify_ga_proof(envelope, public_key=public, expected_type="key-rotation")
            self.assertTrue(verified["valid"])
            self.assertEqual(set(verified["key_ids"]), {public_key_id(public)})
            result = verified["result"]
            assertions = result["assertions"]
            for name in self.contract["key_rotation"]["required_assertions"]:
                self.assertIs(assertions[name], True)
            self.assertGreaterEqual(int(assertions["trust_generation"]), 2)
            self.assertEqual(result["artifacts"], [])

    def test_otlp_probe_source_uses_real_exporter_and_never_serializes_payload_or_headers(self) -> None:
        text = OTLP_PROBE.read_text(encoding="utf-8")
        for item in (
            "OTLPMetricsExporter(service, normalized, headers=headers",
            "exporter.export_once(), exporter.export_once()",
            "ssl.create_default_context()",
            "address.is_global",
            "external OTLP collector must reject the same request without credentials using 401/403",
            "external OTLP live report status is not 2xx",
            "external OTLP live report unauthenticated status is not 401/403",
            '"metrics_payload_in_report": False',
            '"secrets_in_report": False',
            '"artifacts": [{"name": "external-otlp-live-report.json", "sha256": live_sha}]',
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertNotIn('"headers": headers', text)
        self.assertNotIn('"payload": payload', text)

    def test_otlp_workflow_separates_probe_and_operations_signing_authorities(self) -> None:
        text = OTLP_WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "name: production-ga-final-external-otlp",
            "environment: production-ga-external-otlp-probe",
            "environment: production-ga-operations-signing",
            "PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON",
            "PSMATRIX_GA_OPERATIONS_PRIVATE_KEY",
            "PSMATRIX_GA_OPERATIONS_PUBLIC_KEY",
            "probe_final_external_otlp.py run",
            "probe_final_external_otlp.py proof-result",
            "ga proof-create",
            "--type external-otlp",
            "result=verified.get('result')",
            "operations and release GA authorities must be independent",
            "psmatrix-2.0.0-final-external-otlp",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)
        probe_job = text.split("  sign-external-otlp:", 1)[0]
        self.assertNotIn("PSMATRIX_GA_OPERATIONS_PRIVATE_KEY", probe_job)
        self.assertNotIn("PSMATRIX_GA_OPERATIONS_PUBLIC_KEY", probe_job)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_OPERATIONS_PRIVATE_KEY"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON"), 1)
        self.assertLess(text.index("Build and validate unsigned OTLP proof before operations-key access"), text.index("Materialize operations authority"))

    def test_key_rotation_workflow_reuses_exact_signed_release_authority(self) -> None:
        text = ROTATION_WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "name: production-ga-final-key-rotation",
            "environment: production-ga-release-signing",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "signed-release/psmatrix-2.0.0-release-public.pem",
            "ga key-rotation-drill",
            "ga proof-verify",
            "--type key-rotation",
            "result=verified.get('result')",
            "actual_release_authority_rotated':False",
            "psmatrix-2.0.0-final-key-rotation",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_RELEASE_PRIVATE_KEY"), 1)
        self.assertNotIn("PSMATRIX_GA_RELEASE_PRIVATE_KEY", text)
        self.assertNotIn("generate_ed25519_keypair", text)
        self.assertLess(text.index("Revalidate exact signed release authority before private-key access"), text.index("Materialize exact release private authority"))

    def test_source_preflight_reports_eight_of_eleven_producers(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-operations-release-evidence-producers-source-preflight",
            "operations_release_producer_control_changed_paths=6",
            "runtime_source_changes=0",
            "evaluator_producer_sources_present=8",
            "evaluator_producer_sources_required=11",
            "external_otlp_producer_executed=false",
            "key_rotation_producer_executed=false",
            "operations_private_key_read=false",
            "release_private_key_read=false",
            "actual_release_authority_rotated=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
