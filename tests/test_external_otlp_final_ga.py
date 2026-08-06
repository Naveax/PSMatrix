import json
import tempfile
import unittest
from pathlib import Path

from psmatrix import ga


COMMIT = "1" * 40
MANIFEST = "2" * 64
WHEEL = "3" * 64
CERTIFICATE = "4" * 64
REPORT = "5" * 64


class ExternalOTLPFinalGATests(unittest.TestCase):
    def _proof_result(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": "external-otlp",
            "status": "PASS",
            "observed_at": ga.utc_now_iso(),
            "release_commit": COMMIT,
            "artifacts": [
                {
                    "name": "external-otlp-live-report.json",
                    "sha256": REPORT,
                }
            ],
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
                "expected_version": "2.0.0",
                "release_manifest_sha256": MANIFEST,
                "release_wheel_sha256": WHEEL,
                "server_certificate_sha256": CERTIFICATE,
            },
        }

    def _signed_policy(self, root: Path, result: dict) -> tuple[dict, Path]:
        private_key = root / "operations.private.pem"
        public_key = root / "operations.public.pem"
        ga.generate_ed25519_keypair(private_key, public_key)
        envelope = ga.create_ga_proof(
            result,
            private_key=private_key,
            public_key=public_key,
        )
        evidence = root / "external-otlp.dsse.json"
        evidence.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        policy = {
            "requirements": {"external_proof_max_age_days": 14},
            "authorities": {
                "operations": {
                    "public_key": public_key.name,
                    "key_id": ga.public_key_id(public_key),
                }
            },
            "evidence": {
                "external-otlp": {
                    "path": evidence.name,
                    "authority": "operations",
                }
            },
        }
        return policy, root

    def test_hardening_layer_is_installed(self) -> None:
        self.assertTrue(getattr(ga, "_external_otlp_hardened", False))

    def test_complete_external_otlp_proof_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, base = self._signed_policy(root, self._proof_result())
            gate = ga._proof_gate(
                policy,
                base,
                "external-otlp",
                "external-otlp",
                "operations",
            )
        self.assertEqual(gate.status, "PASS", gate.message)
        self.assertEqual(gate.evidence["release_commit"], COMMIT)
        self.assertEqual(gate.evidence["release_manifest_sha256"], MANIFEST)
        self.assertEqual(gate.evidence["release_wheel_sha256"], WHEEL)
        self.assertEqual(gate.evidence["live_report_sha256"], REPORT)
        self.assertEqual(gate.evidence["successful_exports"], 2)

    def test_missing_restart_or_privacy_assertion_fails(self) -> None:
        for field in ("restart_recovery_verified", "source_body_leak_absent"):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result = self._proof_result()
                    result["assertions"][field] = False
                    policy, base = self._signed_policy(root, result)
                    gate = ga._proof_gate(
                        policy,
                        base,
                        "external-otlp",
                        "external-otlp",
                        "operations",
                    )
                self.assertEqual(gate.status, "FAIL")
                self.assertIn(field, gate.message)

    def test_rc_proof_is_not_final_ga_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self._proof_result()
            result["assertions"]["expected_version"] = "2.0.0rc2"
            policy, base = self._signed_policy(root, result)
            gate = ga._proof_gate(
                policy,
                base,
                "external-otlp",
                "external-otlp",
                "operations",
            )
        self.assertEqual(gate.status, "FAIL")
        self.assertIn("final 2.0.0", gate.message)

    def _cross_gate_results(self, *, manifest: str = MANIFEST, wheel: str = WHEEL) -> list:
        return [
            ga.GateResult(
                "validation-summary",
                "PASS",
                "ok",
                {"git_commit": COMMIT},
            ),
            ga.GateResult(
                "signed-release",
                "PASS",
                "ok",
                {
                    "sha256": MANIFEST,
                    "wheel_sha256s": [WHEEL],
                    "source_sha256s": [],
                    "windows_worker_sha256s": [],
                    "windows_certification_kit_sha256s": [],
                    "windows_provisioning_kit_sha256s": [],
                },
            ),
            ga.GateResult(
                "external-otlp",
                "PASS",
                "ok",
                {
                    "release_commit": COMMIT,
                    "release_manifest_sha256": manifest,
                    "release_wheel_sha256": wheel,
                    "deployed_version": "2.0.0",
                },
            ),
        ]

    def test_matching_release_cross_binding_stays_pass(self) -> None:
        results = ga._enforce_cross_gate_bindings(self._cross_gate_results())
        external = next(item for item in results if item.gate == "external-otlp")
        self.assertEqual(external.status, "PASS")

    def test_manifest_or_wheel_mismatch_fails_cross_binding(self) -> None:
        cases = (
            {"manifest": "6" * 64, "wheel": WHEEL},
            {"manifest": MANIFEST, "wheel": "7" * 64},
        )
        for values in cases:
            with self.subTest(values=values):
                results = ga._enforce_cross_gate_bindings(
                    self._cross_gate_results(**values)
                )
                external = next(item for item in results if item.gate == "external-otlp")
                self.assertEqual(external.status, "FAIL")


if __name__ == "__main__":
    unittest.main()
