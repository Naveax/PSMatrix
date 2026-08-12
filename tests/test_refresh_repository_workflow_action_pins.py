from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'ga' / 'refresh_repository_workflow_action_pins.py'


def load_module():
    spec = importlib.util.spec_from_file_location('workflow_pin_refresher', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkflowPinRefresherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workflows = root / '.github' / 'workflows'
        workflows.mkdir(parents=True)
        (workflows / 'a.yml').write_text(
            'steps:\n'
            '  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n'
            '  - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405\n',
            encoding='utf-8',
        )
        (root / 'outside.txt').write_text(
            '34e114876b0b11c390a56381ad16ebd13914f8d5\n', encoding='utf-8'
        )
        return root

    def test_dry_run_reports_without_mutating(self) -> None:
        root = self.make_root()
        result = self.module.refresh(root, apply=False)
        self.assertEqual(result['files_changed'], 1)
        self.assertEqual(result['replacements'], 2)
        self.assertIn('34e114876b0b11c390a56381ad16ebd13914f8d5', (root / '.github/workflows/a.yml').read_text())

    def test_apply_changes_only_workflows_and_is_idempotent(self) -> None:
        root = self.make_root()
        result = self.module.refresh(root, apply=True)
        self.assertEqual(result['files_changed'], 1)
        self.assertEqual(result['replacements'], 2)
        text = (root / '.github/workflows/a.yml').read_text(encoding='utf-8')
        self.assertIn('11d5960a326750d5838078e36cf38b85af677262', text)
        self.assertIn('ece7cb06caefa5fff74198d8649806c4678c61a1', text)
        self.assertIn('34e114876b0b11c390a56381ad16ebd13914f8d5', (root / 'outside.txt').read_text())
        again = self.module.refresh(root, apply=True)
        self.assertEqual(again['files_changed'], 0)
        self.assertEqual(again['replacements'], 0)


if __name__ == '__main__':
    unittest.main()
