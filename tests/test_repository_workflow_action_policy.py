from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'ga' / 'verify_repository_workflow_action_policy.py'


def load_module():
    spec = importlib.util.spec_from_file_location('repo_workflow_action_policy', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryWorkflowActionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self, body: str) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / '.github' / 'workflows'
        workflows.mkdir(parents=True)
        (workflows / 'test.yml').write_text(body, encoding='utf-8')
        return root

    def test_current_pinned_actions_pass(self) -> None:
        root = self.make_root(
            'steps:\n'
            '  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n'
            '  - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1\n'
            '  - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n'
            '  - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n'
            '  - uses: ./local-action\n'
        )
        value = self.module.verify(root)
        self.assertEqual(value['workflow_count'], 1)
        self.assertEqual(value['external_refs'], 4)
        self.assertEqual(value['local_refs'], 1)

    def test_mutable_tag_fails_closed(self) -> None:
        root = self.make_root('steps:\n  - uses: actions/checkout@v4\n')
        with self.assertRaises(self.module.RepositoryWorkflowActionPolicyError):
            self.module.verify(root)

    def test_outdated_known_pin_fails_closed(self) -> None:
        root = self.make_root(
            'steps:\n  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n'
        )
        with self.assertRaises(self.module.RepositoryWorkflowActionPolicyError):
            self.module.verify(root)

    def test_unknown_action_exact_sha_is_inventory_only_and_passes(self) -> None:
        root = self.make_root('steps:\n  - uses: owner/action@' + 'a' * 40 + '\n')
        value = self.module.verify(root)
        self.assertEqual(value['observed'], {'owner/action': ['a' * 40]})

    def test_quoted_and_flow_uses_fail_closed(self) -> None:
        for line in (
            '  - "uses": actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
            '  - {uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262}',
        ):
            with self.subTest(line=line):
                root = self.make_root('steps:\n' + line + '\n')
                with self.assertRaises(self.module.RepositoryWorkflowActionPolicyError):
                    self.module.verify(root)

    def test_reports_all_violations_not_first_only(self) -> None:
        root = self.make_root(
            'steps:\n'
            '  - uses: actions/checkout@v4\n'
            '  - uses: actions/setup-python@v6\n'
        )
        value = self.module.inspect(root)
        self.assertEqual(len(value['violations']), 2)


if __name__ == '__main__':
    unittest.main()
