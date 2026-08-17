from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'ga' / 'verify_verification_hardening_event_head_policy.py'
SOURCE_CERT = ROOT / '.github' / 'workflows' / 'verification-hardening-source-certification.yml'


def load_module():
    spec = importlib.util.spec_from_file_location('hardening_event_head_policy', SCRIPT)
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
        workflows = root / '.github' / 'workflows'
        workflows.mkdir(parents=True)
        (root / self.module.SCANNER_WORKFLOW).write_text(
            'jobs:\n  test:\n    steps:\n'
            '      - name: Scan git-tracked repository for private material\n'
            '        run: >-\n'
            '          python scripts/ga/scan_repository_private_material.py\n'
            '          --root .\n'
            '          --expected-head "${GITHUB_SHA}"\n'
            '      - name: Upload scan receipt\n'
            '        run: echo upload\n',
            encoding='utf-8',
        )
        (root / self.module.SOURCE_CERT_WORKFLOW).write_text(
            'jobs:\n  test:\n    steps:\n'
            '      - name: Resolve exact maintenance base and candidate\n'
            '        run: |\n'
            "          expected = os.environ['GITHUB_SHA'].lower()\n"
            "          if name == 'pull_request':\n"
            "          base_ref = str((pull.get('base') or {}).get('ref') or '')\n"
            "          if base_ref != 'main' or os.environ.get('GITHUB_BASE_REF') != 'main':\n"
            "          base = git('rev-parse', 'origin/main')\n"
            "          first_parent = git('rev-parse', 'HEAD^1')\n"
            "          merge_base = git('merge-base', 'origin/main', 'HEAD')\n"
            '          if first_parent != base or merge_base != base:\n'
            "          elif name == 'push':\n"
            "          completed = subprocess.run(['git','merge-base','--is-ancestor',base,head])\n"
            '          PSMATRIX_VERIFICATION_MAINTENANCE_BASE\n'
            '      - name: Certify immutable historical repository workflow action-pin refresh\n'
            '        run: >-\n'
            '          python scripts/ga/verify_repository_workflow_pin_refresh.py\n'
            f'          --baseline {self.module.HISTORICAL_BASELINE}\n'
            f'          --candidate {self.module.HISTORICAL_CANDIDATE}\n'
            '          --require-candidate-ancestor-of-head\n'
            '          --allow-historical-candidate-additions\n'
            '          --expected-files 76\n'
            '          --expected-replacements 167\n'
            '      - name: Scan exact tracked tree for private material\n'
            '        run: >-\n'
            '          python scripts/ga/scan_repository_private_material.py\n'
            '          --root .\n'
            '          --expected-head "$GITHUB_SHA"\n'
            '      - name: Certify current-base verification maintenance\n'
            '        run: >-\n'
            '          python scripts/ga/certify_verification_hardening_maintenance.py\n'
            '          --base "$PSMATRIX_VERIFICATION_MAINTENANCE_BASE"\n'
            '          --candidate "$GITHUB_SHA"\n'
            '          --historical-workflow-pin-refresh "$RUNNER_TEMP/repository-workflow-pin-refresh.json"\n'
            '          --private-scan "$RUNNER_TEMP/repository-private-material-scan.json"\n',
            encoding='utf-8',
        )
        (root / self.module.POWERSHELL_WORKFLOW).write_text(
            'jobs:\n  test:\n    steps:\n'
            '      - name: Verify exact workflow event revision\n'
            '        run: |\n'
            '          actual="$(git rev-parse HEAD)"\n'
            '          if [[ "$actual" != "$GITHUB_SHA" ]]; then exit 1; fi\n'
            '          echo "workflow_event_head_verified=true"\n'
            '      - name: Parse every tracked PowerShell script\n'
            '        run: echo parse\n',
            encoding='utf-8',
        )
        return root

    def test_exact_event_head_contracts_pass(self) -> None:
        value = self.module.verify(self.make_root())
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['scanner_event_head_bindings'], 2)
        self.assertEqual(value['powershell_event_head_preflights'], 1)
        self.assertEqual(value['historical_pin_refresh_receipt_bindings'], 1)
        self.assertEqual(value['maintenance_base_candidate_bindings'], 1)
        self.assertEqual(value['current_main_merge_parent_bindings'], 1)

    def test_missing_standalone_expected_head_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SCANNER_WORKFLOW
        path.write_text(
            path.read_text(encoding='utf-8').replace(
                '          --expected-head "${GITHUB_SHA}"\n', ''
            ),
            encoding='utf-8',
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_decoy_expected_head_outside_scanner_step_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SCANNER_WORKFLOW
        text = path.read_text(encoding='utf-8').replace(
            '          --expected-head "${GITHUB_SHA}"\n', ''
        )
        text += '      - name: Decoy\n        run: echo --expected-head "${GITHUB_SHA}"\n'
        path.write_text(text, encoding='utf-8')
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_source_cert_expected_head_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SOURCE_CERT_WORKFLOW
        path.write_text(
            path.read_text(encoding='utf-8').replace(
                '          --expected-head "$GITHUB_SHA"\n', ''
            ),
            encoding='utf-8',
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_historical_pin_refresh_binding_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SOURCE_CERT_WORKFLOW
        path.write_text(
            path.read_text(encoding='utf-8').replace(
                '          --historical-workflow-pin-refresh "$RUNNER_TEMP/repository-workflow-pin-refresh.json"\n', ''
            ),
            encoding='utf-8',
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_current_main_merge_parent_binding_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.SOURCE_CERT_WORKFLOW
        path.write_text(
            path.read_text(encoding='utf-8').replace(
                "          first_parent = git('rev-parse', 'HEAD^1')\n", ''
            ),
            encoding='utf-8',
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_stale_pull_request_base_sha_is_rejected(self) -> None:
        root = self.make_root()
        path = root / self.module.SOURCE_CERT_WORKFLOW
        text = path.read_text(encoding='utf-8').replace(
            "          base = git('rev-parse', 'origin/main')\n",
            "          base = str(((event.get('pull_request') or {}).get('base') or {}).get('sha') or '').lower()\n",
        )
        path.write_text(text, encoding='utf-8')
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_missing_powershell_head_compare_fails_closed(self) -> None:
        root = self.make_root()
        path = root / self.module.POWERSHELL_WORKFLOW
        path.write_text(
            path.read_text(encoding='utf-8').replace(
                '          if [[ "$actual" != "$GITHUB_SHA" ]]; then exit 1; fi\n', ''
            ),
            encoding='utf-8',
        )
        with self.assertRaises(self.module.VerificationHardeningEventHeadPolicyError):
            self.module.verify(root)

    def test_source_cert_policy_chain_precedes_scan(self) -> None:
        text = SOURCE_CERT.read_text(encoding='utf-8')
        event = text.index('- name: Verify hardening event-head policy')
        repo = text.index('- name: Verify repository-wide workflow action policy')
        maintenance_range = text.index('- name: Resolve exact maintenance base and candidate')
        pin = text.index('- name: Certify immutable historical repository workflow action-pin refresh')
        scan = text.index('- name: Scan exact tracked tree for private material')
        certify = text.index('- name: Certify current-base verification maintenance')
        self.assertLess(event, repo)
        self.assertLess(repo, maintenance_range)
        self.assertLess(maintenance_range, pin)
        self.assertLess(pin, scan)
        self.assertLess(scan, certify)


if __name__ == '__main__':
    unittest.main()
