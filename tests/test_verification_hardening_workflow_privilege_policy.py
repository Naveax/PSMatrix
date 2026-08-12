from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_verification_hardening_workflow_policy.py"
SOURCE_CERT = ROOT / ".github" / "workflows" / "verification-hardening-source-certification.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("hardening_workflow_policy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningWorkflowPrivilegePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self, permission_entry: str = "contents: read", event: str = "pull_request:") -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        body = (
            "name: test\n\n"
            "on:\n"
            f"  {event}\n\n"
            "permissions:\n"
            f"  {permission_entry}\n\n"
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        )
        for relative in self.module.WORKFLOWS:
            (root / relative).write_text(body, encoding="utf-8")
        return root

    def test_read_only_workflows_pass(self) -> None:
        value = self.module.verify(self.make_root())
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["workflow_count"], 3)
        self.assertEqual(value["job_level_permission_blocks"], 0)

    def test_pull_request_target_fails_closed(self) -> None:
        root = self.make_root(event="pull_request_target:")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_quoted_pull_request_target_fails_closed(self) -> None:
        root = self.make_root(event='"pull_request_target":')
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_write_permission_fails_closed(self) -> None:
        root = self.make_root(permission_entry="contents: write")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_extra_permission_fails_closed(self) -> None:
        root = self.make_root(permission_entry="contents: read\n  actions: read")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_job_level_permission_override_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.WORKFLOWS[0]
        text = path.read_text(encoding="utf-8").replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_quoted_permissions_key_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.WORKFLOWS[0]
        text = path.read_text(encoding="utf-8").replace(
            "permissions:\n  contents: read",
            '"permissions":\n  contents: read',
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_inline_broad_permission_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.WORKFLOWS[0]
        text = path.read_text(encoding="utf-8").replace(
            "permissions:\n  contents: read",
            "permissions: write-all",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(self.module.VerificationHardeningWorkflowPolicyError):
            self.module.verify(root)

    def test_source_cert_verifies_policy_before_scan(self) -> None:
        text = SOURCE_CERT.read_text(encoding="utf-8")
        action_lock = text.index("- name: Verify hardening workflow action lock")
        policy = text.index("- name: Verify hardening workflow privilege policy")
        command = text.index("verify_verification_hardening_workflow_policy.py", policy)
        scan = text.index("- name: Scan exact tracked tree for private material")
        self.assertLess(action_lock, policy)
        self.assertLess(policy, command)
        self.assertLess(command, scan)


if __name__ == "__main__":
    unittest.main()
