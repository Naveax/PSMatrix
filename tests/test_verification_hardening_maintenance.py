import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN_VERIFIER = ROOT / 'scripts' / 'ga' / 'verify_repository_workflow_pin_refresh.py'
MAINTENANCE = ROOT / 'scripts' / 'ga' / 'certify_verification_hardening_maintenance.py'
EVENT_POLICY = ROOT / 'scripts' / 'ga' / 'verify_verification_hardening_event_head_policy.py'
WORKFLOW = ROOT / '.github' / 'workflows' / 'verification-hardening-source-certification.yml'


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ['git', '-C', str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


class VerificationHardeningMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = _load(PIN_VERIFIER, 'verification_pin_refresh_test')
        cls.maintenance = _load(MAINTENANCE, 'verification_maintenance_test')
        cls.event_policy = _load(EVENT_POLICY, 'verification_event_policy_test')

    def test_historical_pin_verifier_can_certify_fixed_candidate_below_current_head(self) -> None:
        with tempfile.TemporaryDirectory(prefix='psmatrix-pin-history-') as temp:
            root = Path(temp)
            _git(root, 'init')
            _git(root, 'config', 'user.email', 'test@example.invalid')
            _git(root, 'config', 'user.name', 'PSMatrix Test')
            workflow = root / '.github' / 'workflows' / 'test.yml'
            workflow.parent.mkdir(parents=True)
            old = next(iter(self.pin.PIN_REPLACEMENTS))
            new = self.pin.PIN_REPLACEMENTS[old]
            workflow.write_text(f'name: test\nsteps:\n  - uses: actions/checkout@{old}\n', encoding='utf-8')
            _git(root, 'add', '.')
            _git(root, 'commit', '-m', 'baseline')
            baseline = _git(root, 'rev-parse', 'HEAD')
            workflow.write_text(f'name: test\nsteps:\n  - uses: actions/checkout@{new}\n', encoding='utf-8')
            _git(root, 'add', '.')
            _git(root, 'commit', '-m', 'pin refresh')
            candidate = _git(root, 'rev-parse', 'HEAD')
            (root / 'README.md').write_text('later maintenance\n', encoding='utf-8')
            _git(root, 'add', '.')
            _git(root, 'commit', '-m', 'later unrelated maintenance')
            head = _git(root, 'rev-parse', 'HEAD')
            self.assertNotEqual(candidate, head)

            result = self.pin.verify(
                root,
                baseline,
                candidate=candidate,
                require_candidate_ancestor_of_head=True,
                expected_files=1,
                expected_replacements=1,
            )
            self.assertEqual(result['certified_head'], candidate)
            self.assertEqual(result['repository_head'], head)
            self.assertTrue(result['historical_candidate_ancestor_of_repository_head'])
            self.assertTrue(result['pin_only_transform_verified'])
            self.assertFalse(result['historical_candidate_additions_outside_pin_proof'])

            with self.assertRaises(self.pin.RepositoryWorkflowPinRefreshError):
                self.pin.verify(root, baseline, candidate=head)
            with self.assertRaisesRegex(self.pin.RepositoryWorkflowPinRefreshError, 'immutable historical candidate'):
                self.pin.verify(root, baseline, candidate=head, allow_historical_candidate_additions=True)

    def test_historical_pin_receipt_is_fixed_and_current_head_bound(self) -> None:
        candidate = 'a' * 40
        receipt = {
            'schema': 1,
            'kind': 'psmatrix.repository-workflow-action-pin-refresh-certification',
            'version': '2.0.0',
            'status': 'PASS',
            'baseline_commit': self.maintenance.HISTORICAL_PIN_BASELINE,
            'certified_head': self.maintenance.HISTORICAL_PIN_CANDIDATE,
            'repository_head': candidate,
            'historical_candidate_ancestor_of_repository_head': True,
            'workflow_file_count': self.maintenance.HISTORICAL_WORKFLOW_FILES,
            'workflow_replacement_count': self.maintenance.HISTORICAL_WORKFLOW_REPLACEMENTS,
            'baseline_files_added': 3,
            'historical_candidate_additions_allowed': True,
            'historical_candidate_additions_outside_pin_proof': True,
            'added_paths_sha256': 'd' * 64,
            'baseline_files_deleted': 0,
            'baseline_modifications_outside_certified_pin_refresh': 0,
            'pin_only_transform_verified': True,
            'pin_only_transform_verified_for_baseline_modifications': True,
            'replacement_map': {'old1': 'new1', 'old2': 'new2'},
            'file_count': 1,
            'files': [{'path': '.github/workflows/example.yml'}],
            'ga_eligible': False,
        }
        self.maintenance._verify_historical_pin_receipt(receipt, candidate)
        bad = dict(receipt)
        bad['certified_head'] = 'b' * 40
        with self.assertRaisesRegex(self.maintenance.VerificationMaintenanceError, 'certified_head'):
            self.maintenance._verify_historical_pin_receipt(bad, candidate)
        stale = dict(receipt)
        stale['repository_head'] = 'c' * 40
        with self.assertRaisesRegex(self.maintenance.VerificationMaintenanceError, 'current candidate HEAD'):
            self.maintenance._verify_historical_pin_receipt(stale, candidate)
        ambiguous = dict(receipt)
        ambiguous['historical_candidate_additions_outside_pin_proof'] = False
        with self.assertRaisesRegex(self.maintenance.VerificationMaintenanceError, 'historical_candidate_additions_outside_pin_proof'):
            self.maintenance._verify_historical_pin_receipt(ambiguous, candidate)

    def test_critical_control_self_modification_requires_companion_test(self) -> None:
        critical = ['scripts/ga/certify_verification_hardening_maintenance.py']
        with self.assertRaisesRegex(self.maintenance.VerificationMaintenanceError, 'companion'):
            self.maintenance._critical_changes_require_tests(critical, set())
        self.maintenance._critical_changes_require_tests(
            critical + ['tests/test_verification_hardening_maintenance.py'],
            set(),
        )
        with self.assertRaisesRegex(self.maintenance.VerificationMaintenanceError, 'may not be deleted'):
            self.maintenance._critical_changes_require_tests(
                critical + ['tests/test_verification_hardening_maintenance.py'],
                set(critical),
            )

    def test_maintenance_certifier_fails_closed_on_runtime_product_source(self) -> None:
        text = MAINTENANCE.read_text(encoding='utf-8')
        self.assertIn("path.startswith('src/psmatrix/')", text)
        self.assertIn('may not certify runtime product source changes', text)
        self.assertIn("'current_base_to_candidate_only': True", text)
        self.assertIn("'historical_publication_proof_separate': True", text)
        self.assertIn("'historical_additions_outside_pin_proof': True", text)
        self.assertIn("'runtime_product_source_certified': False", text)
        self.assertNotIn("f'{self.maintenance.HISTORICAL_PIN_BASELINE}..{candidate}'", text)

    def test_workflow_separates_historical_publication_and_current_maintenance_ranges(self) -> None:
        text = WORKFLOW.read_text(encoding='utf-8')
        required = (
            'Resolve exact maintenance base and candidate',
            "base_ref != 'main'",
            "base = git('rev-parse', 'origin/main')",
            "first_parent = git('rev-parse', 'HEAD^1')",
            "merge_base = git('merge-base', 'origin/main', 'HEAD')",
            'Certify immutable historical repository workflow action-pin refresh',
            f'--baseline {self.maintenance.HISTORICAL_PIN_BASELINE}',
            f'--candidate {self.maintenance.HISTORICAL_PIN_CANDIDATE}',
            '--require-candidate-ancestor-of-head',
            '--allow-historical-candidate-additions',
            'Certify current-base verification maintenance',
            'certify_verification_hardening_maintenance.py',
            '--base "$PSMATRIX_VERIFICATION_MAINTENANCE_BASE"',
            '--candidate "$GITHUB_SHA"',
            '--expected-head "$GITHUB_SHA"',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertNotIn('certify_verification_hardening_source_with_pin_refresh.py', text)
        self.assertLess(
            text.index('Certify immutable historical repository workflow action-pin refresh'),
            text.index('Certify current-base verification maintenance'),
        )

    def test_workflow_scopes_test_triggers_to_verification_surfaces(self) -> None:
        text = WORKFLOW.read_text(encoding='utf-8')
        self.assertNotIn("      - 'tests/**'", text)
        scoped_test_paths = (
            'tests/_verification_hardening_source_certification_base.py',
            'tests/test_final_repository_private_material_scan_certification.py',
            'tests/test_powershell_source_parse_*.py',
            'tests/test_repository_private_material_*.py',
            'tests/test_repository_workflow_action_policy.py',
            'tests/test_verification_hardening_*.py',
        )
        for path in scoped_test_paths:
            with self.subTest(path=path):
                self.assertEqual(text.count(f"      - '{path}'"), 2)
        self.assertIn(
            'group: verification-hardening-source-certification-${{ '
            'github.event.pull_request.head.ref || github.ref }}',
            text,
        )
        self.assertIn('  cancel-in-progress: false', text)

    def test_event_head_policy_accepts_new_split_boundary(self) -> None:
        result = self.event_policy.verify(ROOT)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['historical_pin_refresh_receipt_bindings'], 1)
        self.assertEqual(result['maintenance_base_candidate_bindings'], 1)
        self.assertFalse(result['ga_eligible'])


if __name__ == '__main__':
    unittest.main()
