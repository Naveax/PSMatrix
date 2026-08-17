from __future__ import annotations

import json
import py_compile
import tempfile
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
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_python_authority_tools_compile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            for script in (PROBE, BINDER, ENFORCER):
                py_compile.compile(
                    str(script),
                    cfile=str(target / (script.name + ".pyc")),
                    doraise=True,
                )

    def test_protected_environment_and_secret_set_are_exact(self) -> None:
        self.assertIn("environment: production-ga-external-otlp", self.workflow)
        for secret in (
            "PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE",
            "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PRIVATE_KEY",
            "PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PUBLIC_KEY",
        ):
            self.assertIn(f"secrets.{secret}", self.workflow)

    def test_authentication_value_is_not_a_command_argument(self) -> None:
        self.assertIn("PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE", self.workflow)
        self.assertNotIn("--auth-value", self.workflow)
        self.assertNotIn("--authorization", self.workflow)

    def test_fail_closed_public_endpoint_and_restart_contract(self) -> None:
        for fragment in (
            "https://",
            "release_commit",
            "expected_version",
            "release_manifest_sha256",
            "wheel_sha256",
            "health_url",
            "receipt_url",
            "restart_url",
            "recovery_timeout",
            "poll_interval",
        ):
            self.assertIn(fragment, self.workflow)
        self.assertIn("python scripts/ga/probe_external_otlp.py", self.workflow)
        self.assertIn("python scripts/ga/bind_external_otlp_release.py", self.workflow)
        self.assertIn("python scripts/ga/enforce_external_otlp_report.py", self.workflow)

    def test_release_binding_signing_and_verification_order_is_locked(self) -> None:
        probe_index = self.workflow.index("python scripts/ga/probe_external_otlp.py")
        bind_index = self.workflow.index("python scripts/ga/bind_external_otlp_release.py")
        enforce_index = self.workflow.index("python scripts/ga/enforce_external_otlp_report.py")
        sign_index = self.workflow.index("python -m psmatrix.cli ga proof sign")
        cleanup_index = self.workflow.index("Remove operations authority key files")
        verify_index = self.workflow.index("Verify external OTLP DSSE proof")
        inventory_index = self.workflow.index("Scan evidence and write inventory")
        self.assertLess(probe_index, bind_index)
        self.assertLess(bind_index, enforce_index)
        self.assertLess(enforce_index, sign_index)
        self.assertLess(sign_index, cleanup_index)
        self.assertLess(cleanup_index, verify_index)
        self.assertLess(verify_index, inventory_index)

    def test_authority_contract_and_documentation_match_workflow(self) -> None:
        contract = self.contract
        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(contract["pack_id"], "05-external-otlp")
        self.assertEqual(contract["authority"]["protected_environment"], "production-ga-external-otlp")
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
