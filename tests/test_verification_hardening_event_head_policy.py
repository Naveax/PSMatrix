from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_verification_hardening_event_head_policy.py"
SOURCE_CERT = ROOT / ".github" / "workflows" / "verification-hardening-source-certification.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("hardening_event_head_policy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningEventHeadPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (root / self.module.SCANNER_WORKFLOW).write_text(
            "jobs:\n  test:\n    steps:\n"
            "      - name: Scan git-tracked repository for private material\n"
            "        run: >-\n"
            "          python scripts/ga/scan_repository_private_material.py\n"
            "          --root .\n"
            "          --expected-head \"${GITHUB_SHA}\"\n"
            "      - name: Upload scan receipt\n"
            "        run: echo upload\n",
            encoding="utf-8",
        )
        (root / self.module.SOURCE_CERT_WORKFLOW).write_text(
            "jobs:\n  test:\n    steps:\n"
            "      - name: Scan exact tracked tree for private material\n"
            "        run: >-\n"
            "          python scripts/ga/scan_repository_private_material.py\n"
            "          --root .\n"
            "          --expected-head \"$GITHUB_SHA\"\n"
            "      - name: Certify additive-only verification hardening\n"
            "        run: >-\n"
            "          python scripts/ga/certify_verification_hardening_source.py\n",
            encoding="utf-8",
        )
        (root / self.module.POWERSHELL_WORKFLOW).write_text(
            "jobs:\n  test:\n    steps:\n"
            "      - name: Verify exact workflow event revision\n"
            "        run: |\n"
            "          actual=\"$(git rev-parse HEAD)\"\n"
            "          if [[ \"$actual\" != \"$GITHUB_SHA\" ]]; then exit 1; fi\n"
            "          echo \"workflow_event_head_verified=true\"\n"
            "      - name: Parse every tracked PowerShell script\n"
            "        run: echo parse\n",
            encoding="utf-8",
        )
        return root

    def test_exact_event_head_contracts_pass(self) -> None:
        value = self.module.verify(self.make_root())
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["scanner_event_head_bindings"], 2)
        self.assertEqual(value["powershell_event_head_preflights"], 1)

    def test_missing_standalone_expected_head_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SCANNER_WORKFLOW
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '          --expected-head "${GITHUB_SHA}"\n', ""
            ),
            encoding="utf-8",
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_decoy_expected_head_outside_scanner_step_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SCANNER_WORKFLOW
        text = path.read_text(encoding="utf-8").replace(
            '          --expected-head "${GITHUB_SHA}"\n', ""
        )
        text += (
            "      - name: Decoy\n"
            "        run: echo '--expected-head \"${GITHUB_SHA}\"'\n"
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_source_cert_expected_head_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SOURCE_CERT_WORKFLOW
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '          --expected-head "$GITHUB_SHA"\n', ""
            ),
            encoding="utf-8",
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_powershell_head_compare_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.POWERSHELL_WORKFLOW
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '          if [[ "$actual" != "$GITHUB_SHA" ]]; then exit 1; fi\n', ""
            ),
            encoding="utf-8",
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_source_cert_verifies_event_head_policy_before_scan(self) -> None:
        text = SOURCE_CERT.read_text(encoding="utf-8")
        checkout = text.index("- name: Verify hardening checkout policy")
        event = text.index("- name: Verify hardening event-head policy")
        command = text.index("verify_verification_hardening_event_head_policy.py", event)
        scan = text.index("- name: Scan exact tracked tree for private material")
        self.assertLess(checkout, event)
        self.assertLess(event, command)
        self.assertLess(command, scan)


if __name__ == "__main__":
    unittest.main()
