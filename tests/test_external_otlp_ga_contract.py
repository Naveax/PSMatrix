import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "ga" / "probe_external_otlp.py"
BINDER = ROOT / "scripts" / "ga" / "bind_external_otlp_release.py"
ENFORCER = ROOT / "scripts" / "ga" / "enforce_external_otlp_report.py"
CONTRACT = ROOT / "ga-packs" / "05-external-otlp" / "authority-contract.json"
README = ROOT / "ga-packs" / "05-external-otlp" / "README.md"

COMMIT = "1" * 40
VERSION = "2.0.0rc2"
MANIFEST_DIGEST = "2" * 64
WHEEL_DIGEST = "3" * 64
CERTIFICATE_DIGEST = "4" * 64
PRE_PAYLOAD = "5" * 64
POST_PAYLOAD = "6" * 64


class ExternalOTLPGAContractTests(unittest.TestCase):
    def _write(self, path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _report(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.external-otlp-live-report",
            "status": "PASS",
            "observed_at": "2026-08-06T00:00:00+00:00",
            "external_probe": True,
            "release_commit": COMMIT,
            "expected_version": VERSION,
            "endpoint": "https://otel.example.com/v1/metrics",
            "resolved_addresses": ["93.184.216.34"],
            "supporting_endpoint_addresses": {
                "health": ["93.184.216.34"],
                "receipt": ["93.184.216.34"],
                "restart": ["93.184.216.34"],
            },
            "server_certificate_sha256": CERTIFICATE_DIGEST,
            "authentication": {
                "header_name": "Authorization",
                "credential_value_recorded": False,
                "unauthenticated_status": 401,
                "authenticated": True,
            },
            "ingestion": {
                "request_path": "/v1/metrics",
                "content_type": "application/json",
                "pre_restart_status": 200,
                "post_restart_status": 200,
                "successful_exports": 2,
                "pre_restart_receipt": {
                    "payload_sha256": PRE_PAYLOAD,
                    "collector_instance_id": "collector-a",
                    "ingested_at": "2026-08-06T00:00:01+00:00",
                    "metric_names": ["psmatrix_info"],
                },
                "post_restart_receipt": {
                    "payload_sha256": POST_PAYLOAD,
                    "collector_instance_id": "collector-b",
                    "ingested_at": "2026-08-06T00:00:10+00:00",
                    "metric_names": ["psmatrix_info"],
                },
            },
            "recovery": {
                "restart_status": 202,
                "instance_before": "collector-a",
                "instance_after": "collector-b",
                "instance_changed": True,
                "recovery_seconds": 9.0,
                "maximum_recovery_seconds": 300,
            },
            "privacy": {
                "credential_values_absent": True,
                "private_key_material_absent": True,
                "raw_source_body_absent": True,
                "absolute_paths_absent": True,
            },
        }

    def _proof(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": "external-otlp",
            "status": "PASS",
            "observed_at": "2026-08-06T00:00:00+00:00",
            "release_commit": COMMIT,
            "artifacts": [{"name": "external-otlp-live-report.json", "sha256": "a" * 64}],
            "assertions": {
                "endpoint": "https://otel.example.com/v1/metrics",
                "resolved_addresses": ["93.184.216.34"],
                "external_probe": True,
                "public_dns": True,
                "public_tls": True,
                "collector_external": True,
                "request_path": "/v1/metrics",
                "status_code": 200,
                "post_restart_status_code": 200,
                "authenticated_tls": True,
                "unauthenticated_request_rejected": True,
                "collector_receipt_verified": True,
                "restart_recovery_verified": True,
                "collector_instance_changed": True,
                "recovery_seconds": 9.0,
                "successful_exports": 2,
                "credential_leak_absent": True,
                "private_key_leak_absent": True,
                "source_body_leak_absent": True,
                "absolute_path_leak_absent": True,
                "release_commit_bound": True,
                "release_commit": COMMIT,
                "expected_version": VERSION,
                "server_certificate_sha256": CERTIFICATE_DIGEST,
            },
        }

    def _prepare(self, root: Path) -> tuple[Path, Path]:
        report = root / "external-otlp-live-report.json"
        proof = root / "external-otlp-proof-input.json"
        self._write(report, self._report())
        self._write(proof, self._proof())
        return report, proof

    def _bind(self, root: Path, report: Path, proof: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(BINDER),
                "--report",
                str(report),
                "--proof",
                str(proof),
                "--release-commit",
                COMMIT,
                "--expected-version",
                VERSION,
                "--release-manifest-sha256",
                MANIFEST_DIGEST,
                "--release-wheel-sha256",
                WHEEL_DIGEST,
                "--output",
                str(root / "binding.json"),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _enforce(self, report: Path, proof: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ENFORCER),
                "--report",
                str(report),
                "--proof",
                str(proof),
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

    def test_scripts_are_valid_python(self) -> None:
        for path in (PROBE, BINDER, ENFORCER):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_release_binding_then_enforcement_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report, proof = self._prepare(root)
            bound = self._bind(root, report, proof)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            enforced = self._enforce(report, proof)
        self.assertEqual(enforced.returncode, 0, enforced.stderr)
        result = json.loads(enforced.stdout)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["safe_to_sign"])
        self.assertFalse(result["ga_eligible"])
        self.assertEqual(result["release_manifest_sha256"], MANIFEST_DIGEST)
        self.assertEqual(result["release_wheel_sha256"], WHEEL_DIGEST)

    def test_unauthenticated_2xx_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report, proof = self._prepare(root)
            value = json.loads(report.read_text(encoding="utf-8"))
            value["authentication"]["unauthenticated_status"] = 200
            self._write(report, value)
            bound = self._bind(root, report, proof)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            enforced = self._enforce(report, proof)
        self.assertNotEqual(enforced.returncode, 0)
        self.assertIn("unauthenticated_status", enforced.stderr)

    def test_same_collector_instance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report, proof = self._prepare(root)
            value = json.loads(report.read_text(encoding="utf-8"))
            value["recovery"]["instance_after"] = "collector-a"
            value["recovery"]["instance_changed"] = False
            self._write(report, value)
            bound = self._bind(root, report, proof)
            self.assertNotEqual(bound.returncode, 0)
            self.assertIn("restart recovery", bound.stderr)

    def test_tampered_live_report_after_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report, proof = self._prepare(root)
            bound = self._bind(root, report, proof)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            value = json.loads(report.read_text(encoding="utf-8"))
            value["recovery"]["recovery_seconds"] = 10.0
            self._write(report, value)
            enforced = self._enforce(report, proof)
        self.assertNotEqual(enforced.returncode, 0)
        self.assertIn("exact live report", enforced.stderr)

    def test_source_or_private_key_material_is_rejected(self) -> None:
        cases = ("Write-Host 'secret'", "-----BEGIN PRIVATE KEY-----")
        for marker in cases:
            with self.subTest(marker=marker):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    report, proof = self._prepare(root)
                    value = json.loads(report.read_text(encoding="utf-8"))
                    value["unexpected"] = marker
                    self._write(report, value)
                    enforced = self._enforce(report, proof)
                self.assertNotEqual(enforced.returncode, 0)
                self.assertIn("forbidden secret or source material", enforced.stderr)

    def test_probe_uses_environment_secret_and_bounded_recovery(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn("--auth-env", text)
        self.assertNotIn("--auth-value", text)
        self.assertIn("accepted_errors={401, 403}", text)
        self.assertIn("args.recovery_timeout <= 300", text)
        self.assertIn("collector_instance_id", text)
        self.assertIn("psmatrix.external-otlp-receipt", text)
        self.assertIn("source_body_leak_absent", text)
        self.assertNotIn("auth_value\"", text)

    def test_authority_contract_is_fail_closed(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["authority"]["protected_environment"], "production-ga-external-otlp")
        self.assertTrue(contract["network"]["authentication_required"])
        self.assertEqual(contract["network"]["unauthenticated_statuses"], [401, 403])
        self.assertTrue(contract["release_binding"]["final_evaluator_cross_binding_required"])
        self.assertTrue(contract["recovery"]["collector_restart_required"])
        self.assertEqual(contract["recovery"]["maximum_recovery_seconds"], 300)
        self.assertTrue(contract["privacy"]["raw_source_body_forbidden"])
        self.assertFalse(contract["completion"]["ga_eligible"])
        readme = README.read_text(encoding="utf-8")
        self.assertIn("## Source preflight", readme)
        self.assertIn("## Final evaluator preflight", readme)
        self.assertIn("production-ga-pack05-source-preflight", readme)
        self.assertIn("production-ga-pack05-final-evaluator-preflight", readme)


if __name__ == "__main__":
    unittest.main()
