import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-external-otlp.yml"
CONTRACT = ROOT / "ga-packs" / "05-external-otlp" / "authority-contract.json"
README = ROOT / "ga-packs" / "05-external-otlp" / "README.md"
PROBE = ROOT / "scripts" / "ga" / "probe_external_otlp.py"
BINDER = ROOT / "scripts" / "ga" / "bind_external_otlp_release.py"
ENFORCER = ROOT / "scripts" / "ga" / "enforce_external_otlp_report.py"


class ExternalOTLPWorkflowContractTests(unittest.TestCase):
    def test_python_authority_tools_compile(self) -> None:
        for path in (PROBE, BINDER, ENFORCER):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_protected_environment_and_secret_set_are_exact(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("environment: production-ga-external-otlp", text)
        self.assertIn("runs-on: ubuntu-latest", text)
        for name in (
            "PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE",
            "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PRIVATE_KEY",
            "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PUBLIC_KEY",
        ):
            with self.subTest(name=name):
                self.assertIn(f"secrets.{name}", text)
        self.assertNotIn("permissions:\n  contents: write", text)
        self.assertIn("permissions:\n  contents: read", text)

    def test_authentication_value_is_not_a_command_argument(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("--auth-value", text)
        self.assertIn("--auth-env PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE", text)
        self.assertIn("authentication value leaked into evidence", text)
        self.assertNotRegex(
            text,
            re.compile(
                r"python\s+scripts/ga/probe_external_otlp\.py[\s\S]*"
                r"\$\{\{\s*secrets\.PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE\s*\}\}"
            ),
        )

    def test_release_binding_signing_and_verification_order_is_locked(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        positions = [
            text.index("Execute external collector authority probe"),
            text.index("Bind proof to exact signed release artifacts"),
            text.index("Enforce restart, privacy and release semantics"),
            text.index("Sign and verify operations-authority proof"),
            text.index("Remove operations-authority key material"),
            text.index("Enforce evidence inventory and final status"),
            text.index("Upload external OTLP authority evidence"),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("ga proof-create", text)
        self.assertIn("--type external-otlp", text)
        self.assertIn("ga proof-verify", text)
        self.assertIn("--attestation \"$live/external-otlp.dsse.json\"", text)
        self.assertIn("if: always()", text)
        self.assertIn("if-no-files-found: error", text)

    def test_fail_closed_public_endpoint_and_restart_contract(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for value in (
            "endpoint path must be exactly /v1/metrics",
            "OTLP, health, receipt and restart URLs must be distinct",
            "recovery_timeout must be 30-300",
            "poll_interval must be 1-30",
            "external_collector_proven\": False",
        ):
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertNotIn(
            "PSMATRIX_EXTERNAL_OTLP_EVIDENCE: ${{ runner.temp }}",
            text,
        )

    def test_authority_contract_and_documentation_match_workflow(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(
            contract["authority"]["protected_environment"],
            "production-ga-external-otlp",
        )
        self.assertEqual(
            contract["authority"]["required_protected_secrets"],
            [
                "PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE",
                "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PRIVATE_KEY",
                "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PUBLIC_KEY",
            ],
        )
        self.assertEqual(
            contract["external_workflow"]["status"],
            "READY_FOR_PROTECTED_INPUTS",
        )
        self.assertTrue(contract["external_workflow"]["key_cleanup_before_inventory"])
        self.assertTrue(contract["external_workflow"]["artifact_on_failure"])
        self.assertEqual(contract["release_binding"]["final_evaluator_version"], "2.0.0")
        self.assertFalse(contract["completion"]["ga_eligible"])

        readme = README.read_text(encoding="utf-8")
        self.assertIn("production-ga-external-otlp", readme)
        self.assertIn("PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE", readme)
        self.assertIn("SOURCE_AND_FINAL_EVALUATOR_PREFLIGHT_PASS_EXTERNAL_DEPLOYMENT_PENDING", readme)


if __name__ == "__main__":
    unittest.main()
