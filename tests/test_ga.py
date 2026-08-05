import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from psmatrix.ga import (
    GAGateError,
    create_ga_artifact_attestation,
    create_ga_attestation,
    create_ga_proof,
    evaluate_ga,
    run_key_rotation_drill,
    verify_ga_attestation,
    verify_ga_proof,
    write_ga_template,
)
from psmatrix.lab_provisioning import create_authoritative_matrix_attestation
from psmatrix.recovery import list_recovery_cases, sign_recovery_report
from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair, public_key_id


class GAGateTests(unittest.TestCase):
    def _key(self, root: Path, name: str):
        private = root / "keys" / f"{name}.private.pem"
        public = root / "keys" / f"{name}.pem"
        generate_ed25519_keypair(private, public)
        return private, public

    def _proof(self, path: Path, proof_type: str, assertions: dict, private: Path, public: Path, *, observed_at=None, artifacts=None):
        value = {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": proof_type,
            "status": "PASS",
            "observed_at": observed_at or datetime.now(UTC).isoformat(),
            "assertions": assertions,
            "artifacts": list(artifacts or []),
        }
        path.write_text(json.dumps(create_ga_proof(value, private_key=private, public_key=public)), encoding="utf-8")


    def _security_review_assertions(self, *, report_sha256: str = "d" * 64):
        return {
            "independent_review": True,
            "sections": [
                "architecture", "authentication", "authorization", "sandbox", "supply-chain",
                "recovery", "operations", "privacy", "release-process",
            ],
            "methodologies": [
                "architecture-review", "threat-model-review", "manual-code-review", "test-evidence-review",
            ],
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 2, "info": 1},
            "reviewer": {
                "name": "Independent Reviewer",
                "organization": "External Security Lab",
                "role": "Principal Security Reviewer",
                "contact": "reviewer@example.test",
                "conflict_of_interest": False,
                "key_controlled_by_reviewer": True,
            },
            "reviewed_commit": "a" * 40,
            "reviewed_release_sha256": "b" * 64,
            "review_report_sha256": report_sha256,
            "review_hours": 24,
        }

    def _complete_fixture(self, root: Path):
        (root / "keys").mkdir()
        (root / "evidence").mkdir()
        (root / "release").mkdir()
        roles = {}
        for role in ("release", "ci", "windows-lab", "deployment", "operations", "recovery", "security-review", "vulnerability-scanner"):
            roles[role] = self._key(root, role)

        validation = {
            "schema": 1,
            "kind": "psmatrix.validation-summary",
            "version": "2.0.0",
            "status": "PASS",
            "validated_at": datetime.now(UTC).isoformat(),
            "automated_tests": {"passed": 250, "failed": 0, "skipped": 0, "total": 250},
            "reproducibility": {"source_zip": True, "source_tar_gz": True, "wheel": True},
            "offline_install_exit_code": 0,
            "core_release_signature_valid": True,
            "distribution_signature_valid": True,
        }
        validation_path = root / "evidence" / "validation-summary.json"
        validation_path.write_text(json.dumps(validation), encoding="utf-8")
        validation_attestation = create_ga_artifact_attestation(
            validation_path, artifact_type="validation-summary", observed_at=validation["validated_at"],
            private_key=roles["ci"][0], public_key=roles["ci"][1],
        )
        (root / "evidence" / "validation-summary.dsse.json").write_text(json.dumps(validation_attestation), encoding="utf-8")

        artifact = root / "release" / "psmatrix-2.0.0.whl"
        artifact.write_bytes(b"wheel")
        create_release_manifest(
            [artifact], root / "release" / "psmatrix-2.0.0-release.json", version="2.0.0",
            signing_private_key=roles["release"][0], signing_public_key=roles["release"][1],
        )

        campaigns = [
            {"runtime_id": version, "valid": True, "run_count": 3, "campaign_sha256": char * 64, "image_manifest_sha256": char.upper().lower() * 64}
            for version, char in (("windows-powershell-4.0", "a"), ("windows-powershell-5.0", "b"), ("windows-powershell-5.1", "c"))
        ]
        windows = create_authoritative_matrix_attestation(
            matrix_id="ga-windows", campaigns=campaigns,
            private_key=roles["windows-lab"][0], public_key=roles["windows-lab"][1],
        )
        (root / "evidence" / "windows-authoritative.dsse.json").write_text(json.dumps(windows), encoding="utf-8")

        coverage = {
            "declared": 25, "passed": 25, "incomplete": 0, "failed": 0,
            "missing_required": [], "failed_required": [], "targets": [],
        }
        full = {"schema": 8, "status": "PASS", "finished_at": datetime.now(UTC).isoformat(), "matrix": {"coverage": coverage, "unallowed_differences": 0}}
        full_path = root / "evidence" / "full-matrix-report.json"
        full_path.write_text(json.dumps(full), encoding="utf-8")
        full_attestation = create_ga_artifact_attestation(
            full_path, artifact_type="full-matrix-report", observed_at=full["finished_at"],
            private_key=roles["ci"][0], public_key=roles["ci"][1],
        )
        (root / "evidence" / "full-matrix-report.dsse.json").write_text(json.dumps(full_attestation), encoding="utf-8")

        public = {
            "endpoint": "https://mcp.example.com/mcp",
            "resolved_addresses": ["93.184.216.34"],
            "external_probe": True, "public_dns": True, "public_tls": True,
        }
        self._proof(root / "evidence" / "public-oauth.dsse.json", "public-oauth", {
            **public, "oauth_external": True, "audience_verified": True,
            "scope_verified": True, "token_expiry_verified": True,
        }, *roles["deployment"])
        self._proof(root / "evidence" / "public-mtls.dsse.json", "public-mtls", {
            **public, "client_certificate_required": True, "untrusted_client_rejected": True,
            "certificate_rotation_ready": True,
        }, *roles["deployment"])
        self._proof(root / "evidence" / "external-otlp.dsse.json", "external-otlp", {
            **{**public, "endpoint": "https://otel.example.com/v1/metrics"},
            "collector_external": True, "request_path": "/v1/metrics", "status_code": 200,
        }, *roles["operations"])

        rotation = run_key_rotation_drill(signing_private_key=roles["release"][0], signing_public_key=roles["release"][1])
        (root / "evidence" / "key-rotation.dsse.json").write_text(json.dumps(rotation), encoding="utf-8")

        cases = [{"id": item["id"], "status": "PASS"} for item in list_recovery_cases()]
        recovery_report = {
            "schema": 1, "kind": "psmatrix.recovery-campaign", "status": "PASS",
            "started_at": datetime.now(UTC).isoformat(), "finished_at": datetime.now(UTC).isoformat(), "cases": cases,
            "summary": {"passed": len(cases), "failed": 0, "total": len(cases)},
        }
        recovery = sign_recovery_report(recovery_report, roles["recovery"][0], roles["recovery"][1])
        (root / "evidence" / "recovery.dsse.json").write_text(json.dumps(recovery), encoding="utf-8")

        report_digest = "d" * 64
        self._proof(
            root / "evidence" / "security-review.dsse.json", "security-review",
            self._security_review_assertions(report_sha256=report_digest),
            *roles["security-review"],
            artifacts=[{"name": "security-review-report.json", "sha256": report_digest}],
        )
        self._proof(root / "evidence" / "vulnerability-scan.dsse.json", "vulnerability-scan", {
            "scanners": ["dependency", "static-code"], "source_scanned": True, "dependencies_scanned": True,
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }, *roles["vulnerability-scanner"])

        policy = json.loads(json.dumps(__import__("psmatrix.ga", fromlist=["default_ga_policy"]).default_ga_policy()))
        for role, (_, public_key) in roles.items():
            policy["authorities"][role]["key_id"] = public_key_id(public_key)
        policy_path = root / "ga-policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return policy_path, roles

    def test_missing_evidence_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "ga.json"
            write_ga_template(path)
            result = evaluate_ga(path)
            self.assertEqual(result.status, "INCOMPLETE")
            self.assertEqual(result.summary["INCOMPLETE"], 11)

    def test_complete_fixture_passes_and_attestation_roundtrips(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            evaluation = evaluate_ga(policy)
            self.assertEqual(evaluation.status, "PASS")
            self.assertEqual(evaluation.summary["PASS"], 11)
            envelope = create_ga_attestation(
                evaluation.to_dict(), private_key=roles["release"][0], public_key=roles["release"][1]
            )
            verified = verify_ga_attestation(envelope, public_key=roles["release"][1])
            self.assertTrue(verified["valid"])

    def test_incomplete_or_failed_evaluation_cannot_be_signed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = root / "ga.json"
            write_ga_template(policy)
            private, public = self._key(root, "release")
            with self.assertRaises(GAGateError):
                create_ga_attestation(evaluate_ga(policy).to_dict(), private_key=private, public_key=public)

    def test_local_public_endpoint_proof_fails_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            self._proof(root / "evidence" / "public-oauth.dsse.json", "public-oauth", {
                "endpoint": "https://127.0.0.1/mcp", "resolved_addresses": ["127.0.0.1"],
                "external_probe": True, "public_dns": True, "public_tls": True,
                "oauth_external": True, "audience_verified": True, "scope_verified": True, "token_expiry_verified": True,
            }, *roles["deployment"])
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "public-oauth")
            self.assertEqual(gate.status, "FAIL")
            self.assertEqual(evaluation.status, "FAIL")

    def test_stale_or_high_vulnerability_proof_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            self._proof(root / "evidence" / "vulnerability-scan.dsse.json", "vulnerability-scan", {
                "scanners": ["dependency", "static-code"], "source_scanned": True, "dependencies_scanned": True,
                "findings": {"critical": 0, "high": 1},
            }, *roles["vulnerability-scanner"], observed_at=(datetime.now(UTC) - timedelta(days=45)).isoformat())
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "vulnerability-scan")
            self.assertEqual(gate.status, "FAIL")


    def test_tampered_validation_artifact_is_rejected_despite_valid_signature_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, _roles = self._complete_fixture(root)
            path = root / "evidence" / "validation-summary.json"
            value = json.loads(path.read_text())
            value["automated_tests"]["passed"] += 1
            path.write_text(json.dumps(value), encoding="utf-8")
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "validation-summary")
            self.assertEqual(gate.status, "FAIL")

    def test_policy_cannot_remove_mandatory_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "ga.json"
            write_ga_template(path)
            value = json.loads(path.read_text())
            value["required_gates"] = value["required_gates"][:-1]
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(GAGateError):
                evaluate_ga(path)

    def test_security_review_boolean_only_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            self._proof(root / "evidence" / "security-review.dsse.json", "security-review", {
                "independent_review": True,
                "sections": list(self._security_review_assertions()["sections"]),
                "findings": {"critical": 0, "high": 0},
            }, *roles["security-review"])
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "security-review")
            self.assertEqual(gate.status, "FAIL")
            self.assertIn("methodology", gate.message)

    def test_security_review_conflict_of_interest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            assertions = self._security_review_assertions()
            assertions["reviewer"]["conflict_of_interest"] = True
            self._proof(
                root / "evidence" / "security-review.dsse.json", "security-review", assertions,
                *roles["security-review"], artifacts=[{"name": "review.json", "sha256": "d" * 64}],
            )
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "security-review")
            self.assertEqual(gate.status, "FAIL")
            self.assertIn("conflict-of-interest", gate.message)

    def test_security_review_report_must_be_bound_as_subject(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            assertions = self._security_review_assertions()
            self._proof(
                root / "evidence" / "security-review.dsse.json", "security-review", assertions,
                *roles["security-review"], artifacts=[{"name": "wrong.json", "sha256": "e" * 64}],
            )
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "security-review")
            self.assertEqual(gate.status, "FAIL")
            self.assertIn("not bound", gate.message)

    def test_security_review_commit_binding_must_be_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, roles = self._complete_fixture(root)
            assertions = self._security_review_assertions()
            assertions["reviewed_commit"] = "main"
            self._proof(
                root / "evidence" / "security-review.dsse.json", "security-review", assertions,
                *roles["security-review"], artifacts=[{"name": "review.json", "sha256": "d" * 64}],
            )
            evaluation = evaluate_ga(policy)
            gate = next(item for item in evaluation.gates if item.gate == "security-review")
            self.assertEqual(gate.status, "FAIL")
            self.assertIn("commit binding", gate.message)

    def test_key_rotation_drill_is_signed_and_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private, public = self._key(root, "authority")
            proof = run_key_rotation_drill(signing_private_key=private, signing_public_key=public)
            result = verify_ga_proof(proof, public_key=public, expected_type="key-rotation")
            self.assertTrue(result["valid"])
            self.assertTrue(result["result"]["assertions"]["revocation_enforced"])


if __name__ == "__main__":
    unittest.main()
