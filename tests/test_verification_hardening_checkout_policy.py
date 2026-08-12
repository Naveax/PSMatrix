from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_verification_hardening_checkout_policy.py"
SOURCE_CERT = ROOT / ".github" / "workflows" / "verification-hardening-source-certification.yml"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"


def load_module():
    spec = importlib.util.spec_from_file_location("hardening_checkout_policy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningCheckoutPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        for relative, depth in self.module.WORKFLOW_FETCH_DEPTH.items():
            (root / relative).write_text(
                "jobs:\n  test:\n    steps:\n"
                "      - name: checkout\n"
                f"        uses: actions/checkout@{CHECKOUT_SHA}\n"
                "        with:\n"
                f"          fetch-depth: {depth}\n"
                "          persist-credentials: false\n"
                "      - run: echo ok\n",
                encoding="utf-8",
            )
        return root

    def test_expected_checkout_contracts_pass(self) -> None:
        value = self.module.verify(self.make_root())
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["workflow_count"], 3)

    def test_persisted_credentials_fail_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "ga-repository-private-material-scan.yml"
        text = path.read_text(encoding="utf-8").replace(
            "persist-credentials: false", "persist-credentials: true"
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningCheckoutPolicyError):
            self.module.verify(root)

    def test_wrong_fetch_depth_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "verification-hardening-source-certification.yml"
        text = path.read_text(encoding="utf-8").replace("fetch-depth: 0", "fetch-depth: 1")
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningCheckoutPolicyError):
            self.module.verify(root)

    def test_duplicate_checkout_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
        text = path.read_text(encoding="utf-8") + (
            "      - name: second checkout\n"
            f"        uses: actions/checkout@{CHECKOUT_SHA}\n"
            "        with:\n          fetch-depth: 1\n          persist-credentials: false\n"
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningCheckoutPolicyError):
            self.module.verify(root)

    def test_shorthand_duplicate_checkout_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
        text = path.read_text(encoding="utf-8") + (
            f"      - uses: actions/checkout@{CHECKOUT_SHA}\n"
            "        with:\n          fetch-depth: 1\n          persist-credentials: false\n"
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningCheckoutPolicyError):
            self.module.verify(root)

    def test_source_cert_verifies_checkout_policy_before_scan(self) -> None:
        text = SOURCE_CERT.read_text(encoding="utf-8")
        privilege = text.index("- name: Verify hardening workflow privilege policy")
        checkout = text.index("- name: Verify hardening checkout policy")
        command = text.index("verify_verification_hardening_checkout_policy.py", checkout)
        scan = text.index("- name: Scan exact tracked tree for private material")
        self.assertLess(privilege, checkout)
        self.assertLess(checkout, command)
        self.assertLess(command, scan)


if __name__ == "__main__":
    unittest.main()
