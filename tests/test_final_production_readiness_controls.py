import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
ASSEMBLER = ROOT / "scripts" / "ga" / "assemble_final_production_readiness.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-production-readiness.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-production-readiness-source-preflight.yml"
PRODUCER_ANCHOR = "89372d9432433237abdf677900093b399c4d0868"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


def _load_assembler():
    spec = importlib.util.spec_from_file_location("psmatrix_final_production_readiness_test", ASSEMBLER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalProductionReadinessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.assembler = _load_assembler()

    def _write_receipts(self, root: Path, *, missing=None, missing_path=None, forbidden_field=None) -> None:
        missing = missing or set()
        missing_path = missing_path or set()
        for environment in self.contract["environments"]:
            checks = []
            name = environment["name"]
            for secret in environment.get("required_secrets") or []:
                item = {"name": secret, "source": "secret", "present": (name, "secret", secret) not in missing}
                if forbidden_field:
                    item[forbidden_field] = "forbidden"
                checks.append(item)
            path_vars = set(environment.get("path_vars") or [])
            for var in environment.get("required_vars") or []:
                item = {"name": var, "source": "var", "present": (name, "var", var) not in missing}
                if var in path_vars:
                    item["path_exists"] = (name, var) not in missing_path
                if forbidden_field:
                    item[forbidden_field] = "forbidden"
                checks.append(item)
            status = "PASS" if all(
                item["present"] and (item.get("path_exists", True) is True) for item in checks
            ) else "FAIL"
            receipt = {
                "schema": 1,
                "kind": "psmatrix.production-readiness-receipt",
                "environment": name,
                "status": status,
                "checked_at": "2026-08-10T12:00:00+00:00",
                "checks": checks,
            }
            (root / f"{name}.json").write_text(json.dumps(receipt), encoding="utf-8")

    def test_contract_freezes_exact_twelve_environment_set(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-production-readiness-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["producer_source_anchor"], PRODUCER_ANCHOR)
        self.assertEqual(value["final_release_commit"], FINAL_COMMIT)
        environments = value["environments"]
        self.assertEqual(len(environments), 12)
        self.assertEqual(len({item["name"] for item in environments}), 12)
        expected = {
            "production-ga-release-signing",
            "production-ga-windows-lab",
            "production-ga-ci-signing",
            "production-ga-full-matrix",
            "production-ga-public-auth-probe",
            "production-ga-deployment-signing",
            "production-ga-external-otlp-probe",
            "production-ga-operations-signing",
            "production-ga-recovery-signing",
            "production-ga-security-review-signing",
            "production-ga-vulnerability-scanner-signing",
            "production-ga-root-signing",
        }
        self.assertEqual({item["name"] for item in environments}, expected)
        full = next(item for item in environments if item["name"] == "production-ga-full-matrix")
        self.assertEqual(full["runner"], "NAVEAX")
        self.assertEqual(
            full["path_vars"],
            ["PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT", "PSMATRIX_FULL_MATRIX_HOME"],
        )
        self.assertEqual(value["summary_contract"]["required_environment_count"], 12)
        self.assertEqual(value["summary_contract"]["producer_source_coverage_required"], 11)
        self.assertTrue(value["summary_contract"]["environment_readiness_is_not_ga_readiness"])

    def test_contract_has_no_duplicate_required_names_within_environment(self) -> None:
        for environment in self.contract["environments"]:
            secrets = list(environment.get("required_secrets") or [])
            variables = list(environment.get("required_vars") or [])
            self.assertEqual(len(secrets), len(set(secrets)), environment["name"])
            self.assertEqual(len(variables), len(set(variables)), environment["name"])
            self.assertFalse(set(secrets) & set(variables), environment["name"])
            self.assertTrue(set(environment.get("path_vars") or []) <= set(variables))

    def test_clean_twelve_receipts_pass_environment_readiness_but_never_ga_readiness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-readiness-pass-") as temp:
            root = Path(temp)
            receipts = root / "receipts"
            receipts.mkdir()
            self._write_receipts(receipts)
            output = root / "summary.json"
            result = self.assembler.assemble(contract_path=CONTRACT, receipts_dir=receipts, output=output)
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["environment_readiness"])
            self.assertEqual(result["environment_passed"], 12)
            self.assertEqual(result["environment_failed"], 0)
            self.assertEqual(result["producer_source_coverage"], 11)
            self.assertFalse(result["secret_values_observed"])
            self.assertFalse(result["secret_hashes_observed"])
            self.assertFalse(result["secret_lengths_observed"])
            self.assertFalse(result["production_evidence_runs_complete"])
            self.assertFalse(result["production_evaluator_ready"])
            self.assertFalse(result["final_ga_evaluator_invoked"])
            self.assertFalse(result["ga_eligible"])

    def test_missing_secret_produces_fail_summary_without_secret_value(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-readiness-missing-") as temp:
            root = Path(temp)
            receipts = root / "receipts"
            receipts.mkdir()
            missing = {("production-ga-root-signing", "secret", "PSMATRIX_GA_ROOT_PRIVATE_KEY")}
            self._write_receipts(receipts, missing=missing)
            result = self.assembler.assemble(contract_path=CONTRACT, receipts_dir=receipts, output=root / "summary.json")
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["environment_readiness"])
            self.assertEqual(result["environment_failed"], 1)
            self.assertEqual(result["failed_environments"], ["production-ga-root-signing"])
            row = next(item for item in result["environments"] if item["environment"] == "production-ga-root-signing")
            self.assertEqual(row["missing"], ["secret:PSMATRIX_GA_ROOT_PRIVATE_KEY"])
            self.assertNotIn("value", json.dumps(result).lower())

    def test_forbidden_value_hash_or_length_fields_are_rejected(self) -> None:
        for forbidden in ("value", "sha256", "length"):
            with tempfile.TemporaryDirectory(prefix=f"psmatrix-readiness-{forbidden}-") as temp:
                root = Path(temp)
                receipts = root / "receipts"
                receipts.mkdir()
                self._write_receipts(receipts, forbidden_field=forbidden)
                with self.subTest(forbidden=forbidden), self.assertRaises(self.assembler.ProductionReadinessError):
                    self.assembler.assemble(contract_path=CONTRACT, receipts_dir=receipts, output=root / "summary.json")

    def test_missing_full_matrix_path_fails_even_when_variable_is_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-readiness-path-") as temp:
            root = Path(temp)
            receipts = root / "receipts"
            receipts.mkdir()
            self._write_receipts(
                receipts,
                missing_path={("production-ga-full-matrix", "PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT")},
            )
            result = self.assembler.assemble(contract_path=CONTRACT, receipts_dir=receipts, output=root / "summary.json")
            self.assertEqual(result["status"], "FAIL")
            row = next(item for item in result["environments"] if item["environment"] == "production-ga-full-matrix")
            self.assertEqual(row["missing"], [])
            self.assertEqual(row["missing_paths"], ["PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT"])

    def test_workflow_has_exact_twelve_protected_environments_and_one_naveax_job(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for environment in self.contract["environments"]:
            needle = f"environment: {environment['name']}"
            self.assertEqual(text.count(needle), 1, needle)
        self.assertEqual(text.count("runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]"), 1)
        self.assertIn("RUNNER_NAME -ne 'NAVEAX'", text)
        self.assertIn("pattern: psmatrix-readiness-*", text)
        self.assertIn("merge-multiple: true", text)
        self.assertIn("--require-pass", text)
        self.assertIn("production_evidence_runs_complete=false", text)
        self.assertIn("production_evaluator_ready=false", text)
        self.assertIn("ga_eligible=false", text)

    def test_workflow_receipts_never_serialize_secret_values_hashes_or_lengths(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden in (
            "toJSON(secrets)",
            "toJson(secrets)",
            "hashlib.sha256(os.environ",
            "len(os.environ",
            '"value":os.environ',
            '"sha256":',
            '"length":',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn('"present":bool(os.environ.get(', text)
        self.assertNotIn("echo $CHECK_SECRET_", text)
        self.assertNotIn("Write-Host $env:CHECK_SECRET_", text)

    def test_source_preflight_freezes_five_paths_and_no_execution_claims(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-production-readiness-source-preflight",
            "production_readiness_control_changed_paths=5",
            "runtime_source_changes=0",
            "evaluator_producer_sources_present=11",
            "evaluator_producer_sources_required=11",
            "readiness_workflow_executed=false",
            "environment_receipts_observed=false",
            "all_environments_ready=false",
            "production_evidence_runs_complete=false",
            "production_evaluator_ready=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
