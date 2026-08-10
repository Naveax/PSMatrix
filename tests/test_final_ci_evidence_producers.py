import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.ga import default_ga_policy
from psmatrix.util import atomic_write_json, sha256_file


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ci-evidence-producer-contract.json"
EVALUATOR_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
VALIDATION_BUILDER = ROOT / "scripts" / "ga" / "build_final_validation_summary.py"
MATRIX_PROBE = ROOT / "scripts" / "ga" / "full_matrix_probe.ps1"
VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-validation-summary.yml"
MATRIX_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-full-runtime-matrix.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-ci-evidence-producers-source-preflight.yml"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
EVALUATOR_ANCHOR = "c5d4e14b36b84bddb7145762bbc4e4f1fe9a35f3"


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_final_validation_builder_test", VALIDATION_BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalCIEvidenceProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.evaluator = json.loads(EVALUATOR_CONTRACT.read_text(encoding="utf-8"))
        cls.builder = _load_builder()

    def test_contract_freezes_two_shared_ci_producers_and_external_prerequisites(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-ci-evidence-producer-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["final_release_commit"], FINAL_COMMIT)
        self.assertEqual(value["evaluator_anchor"], EVALUATOR_ANCHOR)
        validation = value["validation_summary"]
        self.assertEqual(validation["workflow"], "production-ga-final-validation-summary")
        self.assertEqual(validation["artifact"], "psmatrix-2.0.0-final-validation-summary")
        self.assertTrue(validation["rebuild_final_artifacts"])
        self.assertTrue(validation["offline_install_required"])
        self.assertTrue(validation["platform_neutral_suite_required"])
        self.assertFalse(validation["suite_skips_allowed"])
        matrix = value["full_runtime_matrix"]
        self.assertEqual(matrix["workflow"], "production-ga-final-full-runtime-matrix")
        self.assertEqual(matrix["artifact"], "psmatrix-2.0.0-final-full-runtime-matrix")
        self.assertEqual(matrix["canonical_target_count"], 25)
        self.assertEqual(matrix["remote_target_count"], 13)
        self.assertEqual(matrix["ready_target_count_required"], 25)
        self.assertEqual(matrix["differential_mode"], "strict")
        self.assertFalse(matrix["inline_allowances_allowed"])
        self.assertFalse(matrix["nonempty_allowance_manifest_allowed"])
        self.assertEqual(matrix["endpoint_environment"], "production-ga-full-matrix")
        self.assertEqual(matrix["endpoint_root_variable"], "PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT")
        authority = value["ci_authority"]
        self.assertEqual(authority["environment"], "production-ga-ci-signing")
        self.assertEqual(authority["private_key_secret"], "PSMATRIX_GA_CI_PRIVATE_KEY")
        self.assertEqual(authority["public_key_secret"], "PSMATRIX_GA_CI_PUBLIC_KEY")
        self.assertFalse(authority["private_key_allowed_on_persistent_self_hosted_runner"])
        self.assertTrue(authority["validation_and_matrix_must_share_exact_authority"])

    def test_evaluator_contract_matches_new_producer_workflows_and_runtime_ci_authority(self) -> None:
        policy = default_ga_policy()
        expected = {
            "validation-summary": self.contract["validation_summary"],
            "complete-runtime-matrix": self.contract["full_runtime_matrix"],
        }
        for gate, producer in expected.items():
            with self.subTest(gate=gate):
                evaluator = self.evaluator["evidence_sources"][gate]
                self.assertEqual(evaluator["workflow"], producer["workflow"])
                self.assertEqual(evaluator["workflow_path"], producer["workflow_path"])
                self.assertEqual(evaluator["artifact"], producer["artifact"])
                self.assertEqual(evaluator["authority"], "ci")
                self.assertEqual(policy["evidence"][gate]["authority"], "ci")

    def test_validation_builder_is_exact_source_bound_rebuild_bound_and_offline(self) -> None:
        text = VALIDATION_BUILDER.read_text(encoding="utf-8")
        required = (
            f'_FINAL_COMMIT = "{FINAL_COMMIT}"',
            "run_suite(repo_root: Path",
            'env["PYTHONPATH"] = str(repo / "src")',
            '"test_integration.py"',
            "OciRuntimeTests.test_image_reference_validation",
            "Final validation target is not clean PASS",
            "Signed final artifact differs from deterministic rebuild",
            '"source_zip": _reproducible',
            '"source_tar_gz": _reproducible',
            '"wheel": _reproducible',
            '"PIP_NO_INDEX": "1"',
            '"--no-index"',
            '"core_release_signature_valid": True',
            '"distribution_signature_valid": True',
            '"offline_install_exit_code"',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_GA_CI_PRIVATE_KEY",
            "requests.get",
            "Invoke-WebRequest",
            '"skipped": 1',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_rebuild_validator_rejects_signed_artifact_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ci-rebuild-test-") as temp:
            root = Path(temp)
            rebuilt = root / "rebuilt"
            signed = root / "signed"
            rebuilt.mkdir()
            signed.mkdir()
            artifacts = []
            for index, name in enumerate(sorted(self.builder._RELEASE_ARTIFACTS), start=1):
                data = f"artifact-{index}-{name}".encode()
                (rebuilt / name).write_bytes(data)
                (signed / name).write_bytes(data)
                artifacts.append({"name": name, "sha256": sha256_file(rebuilt / name), "size": len(data)})
            atomic_write_json(
                rebuilt / "psmatrix-2.0.0-windows-authority-final-staging.json",
                {
                    "status": "READY_FOR_FINAL_RELEASE_LOCK_REVIEW",
                    "version": "2.0.0",
                    "release_commit": FINAL_COMMIT,
                    "private_key_read": False,
                    "release_artifacts_signed": False,
                    "artifacts": artifacts,
                    "reproducibility": {
                        "source_zip": {"reproducible": True},
                        "source_tar_gz": {"reproducible": True},
                        "wheel": {"reproducible": True},
                    },
                },
            )
            value = self.builder._verify_rebuilt_release(rebuilt, signed)
            self.assertEqual(value, {"source_zip": True, "source_tar_gz": True, "wheel": True})
            drift = next(iter(sorted(self.builder._RELEASE_ARTIFACTS)))
            (signed / drift).write_bytes(b"drift")
            with self.assertRaisesRegex(self.builder.FinalValidationError, "differs from deterministic rebuild"):
                self.builder._verify_rebuilt_release(rebuilt, signed)

    def test_matrix_probe_is_bounded_version_neutral_and_not_a_fake_runtime_identity(self) -> None:
        text = MATRIX_PROBE.read_text(encoding="utf-8")
        self.assertIn("Set-StrictMode -Version 2.0", text)
        self.assertIn("PSMATRIX_FINAL_GA_FULL_MATRIX_PROBE_V1", text)
        for forbidden in ("$PSVersionTable", "powershell-7", "windows-powershell", "Start-Process", "Invoke-WebRequest"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_validation_workflow_keeps_ci_private_key_off_naveax_and_after_unsigned_evidence(self) -> None:
        text = VALIDATION_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-final-validation-summary",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "Run exact final-source platform-neutral validation suite",
            "Rebuild exact final artifacts deterministically from frozen source",
            "Build release-bound validation summary and perform offline install",
            "Upload unsigned validation evidence for protected CI signing",
            "runs-on: ubuntu-latest",
            "environment: production-ga-ci-signing",
            "PSMATRIX_GA_CI_PRIVATE_KEY",
            "PSMATRIX_GA_CI_PUBLIC_KEY",
            "ga artifact-sign",
            "ga artifact-verify",
            "signed_validation_summary=PASS",
            "psmatrix-2.0.0-final-validation-summary",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_CI_PRIVATE_KEY"), 1)
        secret = text.index("Materialize CI authority, sign exact summary, verify, and remove private key")
        unsigned = text.index("Upload unsigned validation evidence for protected CI signing")
        self.assertLess(unsigned, secret)
        compute_prefix = text[: text.index("sign-validation-summary:")]
        self.assertNotIn("PSMATRIX_GA_CI_PRIVATE_KEY", compute_prefix)

    def test_matrix_workflow_requires_25_ready_strict_real_execution_and_protected_signing(self) -> None:
        text = MATRIX_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-final-full-runtime-matrix",
            "environment: production-ga-full-matrix",
            "PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT",
            "canonical matrix cardinality mismatch",
            "targets=25 remote=13 differential=strict",
            "Require all twenty-five matrix targets READY before execution",
            "ready=25/25",
            "Execute strict canonical twenty-five-target matrix",
            "--differential strict",
            "validate_canonical_full_matrix_report",
            "full release-binding",
            "Upload unsigned full-matrix evidence for protected CI signing",
            "environment: production-ga-ci-signing",
            "PSMATRIX_GA_CI_PRIVATE_KEY",
            "full attest",
            "full verify-attestation",
            "signed_full_runtime_matrix=PASS targets=25",
            "psmatrix-2.0.0-final-full-runtime-matrix",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_CI_PRIVATE_KEY"), 1)
        compute_prefix = text[: text.index("sign-full-matrix:")]
        self.assertNotIn("PSMATRIX_GA_CI_PRIVATE_KEY", compute_prefix)
        self.assertNotIn("windows-authority-rc4", text)
        self.assertNotIn("ga_eligible=true", text)

    def test_source_preflight_reports_four_of_eleven_producers_after_this_layer(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-ci-evidence-producers-source-preflight",
            "final-ci-evidence-producer-contract.json",
            "ga-final-validation-summary.yml",
            "ga-final-full-runtime-matrix.yml",
            "build_final_validation_summary.py",
            "full_matrix_probe.ps1",
            "tests.test_final_ci_evidence_producers",
            "ci_producer_control_changed_paths=7",
            "runtime_source_changes=0",
            "evaluator_producer_sources_present=4",
            "evaluator_producer_sources_required=11",
            "validation_producer_executed=false",
            "full_matrix_producer_executed=false",
            "ci_private_key_read=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
