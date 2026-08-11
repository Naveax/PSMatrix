from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_verification_hardening_action_lock.py"
WORKFLOW = ROOT / ".github" / "workflows" / "verification-hardening-source-certification.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("hardening_action_lock_verifier", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningActionLockVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / ".github" / "workflows"
        scripts = root / "scripts" / "ga"
        workflows.mkdir(parents=True)
        scripts.mkdir(parents=True)
        lock = {
            "schema": 1,
            "kind": "psmatrix.verification-hardening-action-lock",
            "version": "2.0.0",
            "actions": {
                "actions/checkout": {"commit": "1" * 40, "major_family": "v4"},
                "actions/setup-python": {"commit": "2" * 40, "major_family": "v5"},
                "actions/upload-artifact": {"commit": "3" * 40, "major_family": "v4"},
            },
        }
        (scripts / "verification-hardening-action-lock.json").write_text(
            json.dumps(lock), encoding="utf-8"
        )
        (workflows / "ga-repository-private-material-scan.yml").write_text(
            "steps:\n  - uses: actions/checkout@" + "1" * 40 + "\n"
            "  - uses: actions/setup-python@" + "2" * 40 + "\n"
            "  - uses: actions/upload-artifact@" + "3" * 40 + "\n",
            encoding="utf-8",
        )
        (workflows / "verification-hardening-source-certification.yml").write_text(
            "steps:\n  - uses: actions/checkout@" + "1" * 40 + "\n"
            "  - uses: actions/upload-artifact@" + "3" * 40 + "\n",
            encoding="utf-8",
        )
        (workflows / "powershell-source-parse-diagnostic.yml").write_text(
            "steps:\n  - uses: actions/checkout@" + "1" * 40 + "\n",
            encoding="utf-8",
        )
        return root

    def test_current_minimal_locked_workflows_pass(self) -> None:
        value = self.module.verify(self.make_root())
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["workflow_count"], 3)
        self.assertEqual(value["locked_action_count"], 3)
        self.assertEqual(value["checked_uses_count"], 6)

    def test_mutable_action_reference_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
        path.write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningActionLockError):
            self.module.verify(root)

    def test_wrong_locked_sha_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
        path.write_text("steps:\n  - uses: actions/checkout@" + "9" * 40 + "\n", encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningActionLockError):
            self.module.verify(root)

    def test_unlisted_action_fails_closed(self) -> None:
        root = self.make_root()
        path = root / ".github" / "workflows" / "powershell-source-parse-diagnostic.yml"
        path.write_text("steps:\n  - uses: owner/unlisted@" + "4" * 40 + "\n", encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningActionLockError):
            self.module.verify(root)

    def test_source_cert_verifies_lock_before_private_scan(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        verify = text.index("- name: Verify hardening workflow action lock")
        command = text.index("verify_verification_hardening_action_lock.py", verify)
        scan = text.index("- name: Scan exact tracked tree for private material")
        self.assertLess(verify, command)
        self.assertLess(command, scan)


if __name__ == "__main__":
    unittest.main()
