from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'ga' / 'verify_repository_workflow_pin_refresh.py'
OLD = '34e114876b0b11c390a56381ad16ebd13914f8d5'
NEW = '11d5960a326750d5838078e36cf38b85af677262'


def load_module():
    spec = importlib.util.spec_from_file_location('workflow_pin_refresh', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryWorkflowPinRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init')
        self.git('config', 'user.email', 'ci@example.invalid')
        self.git('config', 'user.name', 'PSMatrix CI')
        workflow = self.root / '.github' / 'workflows' / 'test.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_text(f'steps:\n  - uses: actions/checkout@{OLD}\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-m', 'baseline')
        self.baseline = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args: str) -> str:
        completed = subprocess.run(
            ['git', '-C', str(self.root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False,
            timeout=20,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout

    def commit_refresh(self, extra: str = '') -> None:
        path = self.root / '.github' / 'workflows' / 'test.yml'
        path.write_text(f'steps:\n  - uses: actions/checkout@{NEW}\n{extra}', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-m', 'refresh')

    def test_exact_pin_only_refresh_passes_and_binds_bytes(self) -> None:
        self.commit_refresh()
        value = self.module.verify(
            self.root, self.baseline, expected_files=1, expected_replacements=1
        )
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['file_count'], 1)
        self.assertEqual(value['replacement_count'], 1)
        self.assertTrue(value['pin_only_transform_verified'])
        self.assertEqual(len(value['files'][0]['baseline_sha256']), 64)
        self.assertEqual(len(value['files'][0]['current_sha256']), 64)

    def test_unrelated_workflow_byte_change_fails_closed(self) -> None:
        self.commit_refresh(extra='  # unrelated change\n')
        with self.assertRaises(self.module.RepositoryWorkflowPinRefreshError):
            self.module.verify(self.root, self.baseline)

    def test_non_workflow_baseline_modification_fails_closed(self) -> None:
        (self.root / 'README.md').write_text('baseline\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-m', 'add readme')
        baseline = self.git('rev-parse', 'HEAD').strip()
        self.commit_refresh()
        (self.root / 'README.md').write_text('changed\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-m', 'modify readme')
        with self.assertRaises(self.module.RepositoryWorkflowPinRefreshError):
            self.module.verify(self.root, baseline)

    def test_deletion_fails_closed(self) -> None:
        self.git('rm', '.github/workflows/test.yml')
        self.git('commit', '-m', 'delete workflow')
        with self.assertRaises(self.module.RepositoryWorkflowPinRefreshError):
            self.module.verify(self.root, self.baseline)

    def test_expected_counts_are_enforced(self) -> None:
        self.commit_refresh()
        with self.assertRaises(self.module.RepositoryWorkflowPinRefreshError):
            self.module.verify(self.root, self.baseline, expected_files=2)
        with self.assertRaises(self.module.RepositoryWorkflowPinRefreshError):
            self.module.verify(self.root, self.baseline, expected_replacements=2)


if __name__ == '__main__':
    unittest.main()
