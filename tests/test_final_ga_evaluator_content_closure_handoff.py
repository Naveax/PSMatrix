from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-FinalGAEvaluatorContentClosureHandoff.ps1"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
GATES = (
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
)


def readiness_summary() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary",
        "version": "2.0.0",
        "status": "PASS",
        "environment_count": 12,
        "environment_passed": 12,
        "environment_failed": 0,
        "environment_readiness": True,
        "secret_values_observed": False,
        "secret_hashes_observed": False,
        "secret_lengths_observed": False,
        "production_evidence_runs_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def readiness_verification() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary-verification",
        "version": "2.0.0",
        "status": "PASS",
        "exact_head": HEAD,
        "environment_count": 12,
        "verified_environment_count": 12,
        "required_check_count": 41,
        "verified_check_count": 41,
        "summary_content_verified": True,
        "production_readiness_verified": True,
        "production_evidence_runs_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def content_closure() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": HEAD,
        "required_gate_count": 11,
        "api_verified_gate_count": 11,
        "content_verified_gate_count": 11,
        "gates": [{"gate": gate, "run_id": 1000 + index, "content_verified": True} for index, gate in enumerate(GATES, start=1)],
        "all_api_artifact_origins_verified": True,
        "all_materialized_trees_verified": True,
        "all_repository_owned_semantic_verifiers_passed": True,
        "all_gate_contents_verified": True,
        "public_auth_cross_gate_semantics_verified": True,
        "all_runs_distinct": True,
        "all_artifacts_distinct": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_root_private_key_read": False,
        "ga_eligible": False,
    }


def content_closure_verification(file_sha256: str) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": HEAD,
        "verified_gate_count": 11,
        "source_binding_receipt_count": 10,
        "repository_owned_rederivation": True,
        "closure_exactly_recomputed": True,
        "content_closure_file_sha256": file_sha256,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


class FinalGAEvaluatorContentClosureHandoffTests(unittest.TestCase):
    def run_handoff(self, ready: dict[str, object], verified: dict[str, object], closure: dict[str, object], closure_verification_override: dict[str, object] | None = None) -> subprocess.CompletedProcess[str]:
        pwsh = shutil.which("pwsh")
        if not pwsh:
            self.skipTest("pwsh required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary_path = root / "readiness-summary.json"
            verification_path = root / "readiness-verification.json"
            closure_path = root / "content-closure.json"
            closure_verification_path = root / "content-closure-verification.json"
            summary_path.write_text(json.dumps(ready) + "\n", encoding="utf-8")
            verification_path.write_text(json.dumps(verified) + "\n", encoding="utf-8")
            closure_path.write_text(json.dumps(closure) + "\n", encoding="utf-8")
            closure_sha256 = hashlib.sha256(closure_path.read_bytes()).hexdigest()
            closure_verification_value = closure_verification_override or content_closure_verification(closure_sha256)
            closure_verification_path.write_text(json.dumps(closure_verification_value) + "\n", encoding="utf-8")
            return subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-ReadinessSummary",
                    str(summary_path),
                    "-ReadinessVerification",
                    str(verification_path),
                    "-ContentClosure",
                    str(closure_path),
                    "-ContentClosureVerification",
                    str(closure_verification_path),
                    "-DryRun",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )

    def test_verified_readiness_and_byte_bound_reverified_content_closure_reach_dry_run_dispatch(self) -> None:
        completed = self.run_handoff(readiness_summary(), readiness_verification(), content_closure())
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("final_ga_evaluator_content_closure_handoff=PASS", completed.stdout)
        self.assertIn("verified_evidence_content=11/11", completed.stdout)
        self.assertIn("content_closure_exactly_rederived=true", completed.stdout)
        self.assertIn("content_closure_file_digest_bound=true", completed.stdout)
        self.assertIn("input_count=11", completed.stdout)
        self.assertIn("workflow=ga-final-evaluator.yml", completed.stdout)
        self.assertIn("production_ga_workflow_dispatched=false", completed.stdout)
        self.assertIn("ga_eligible=false", completed.stdout)

    def test_content_closure_flag_failure_blocks_dispatch(self) -> None:
        closure = content_closure()
        closure["all_gate_contents_verified"] = False
        completed = self.run_handoff(readiness_summary(), readiness_verification(), closure)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("all_gate_contents_verified", completed.stdout)

    def test_readiness_and_content_heads_must_match(self) -> None:
        verified = readiness_verification()
        verified["exact_head"] = "a" * 40
        completed = self.run_handoff(readiness_summary(), verified, content_closure())
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("same exact execution head", completed.stdout)

    def test_duplicate_run_ids_fail_closed(self) -> None:
        closure = content_closure()
        closure["gates"][1]["run_id"] = closure["gates"][0]["run_id"]
        completed = self.run_handoff(readiness_summary(), readiness_verification(), closure)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exact and distinct", completed.stdout)

    def test_wrong_reverification_file_digest_fails_closed(self) -> None:
        bad = content_closure_verification("0" * 64)
        completed = self.run_handoff(readiness_summary(), readiness_verification(), content_closure(), bad)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("file bytes differ", completed.stdout)

    def test_unrederived_closure_receipt_fails_closed(self) -> None:
        closure = content_closure()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "closure.json"
            path.write_text(json.dumps(closure) + "\n", encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        bad = content_closure_verification(digest)
        bad["closure_exactly_recomputed"] = False
        completed = self.run_handoff(readiness_summary(), readiness_verification(), closure, bad)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("closure_exactly_recomputed", completed.stdout)

    def test_source_uses_named_splatting_reverification_and_only_final_evaluator_workflow(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("@operatorArgs", text)
        self.assertIn(".github/workflows/ga-final-evaluator.yml", text)
        self.assertIn("psmatrix.final-ga-evidence-content-closure", text)
        self.assertIn("psmatrix.final-ga-evidence-content-closure-verification", text)
        self.assertIn("content_closure_file_sha256", text)
        self.assertIn("Get-FileHash", text)
        self.assertIn("psmatrix.production-readiness-summary-verification", text)
        self.assertIn("ga_root_private_key_read=false", text)
        self.assertIn("ga_eligible=false", text)


if __name__ == "__main__":
    unittest.main()
