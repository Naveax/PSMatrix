from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCANNER_PATH = ROOT / 'scripts' / 'ga' / 'scan_repository_private_material.py'
HISTORICAL_PIN_BASELINE = '3ffc6b6d7cd58d64224f780aa819b50f50f72491'
HISTORICAL_PIN_CANDIDATE = '3b06770cb925add391f4552e5f1cbd0ed6aa96b5'
HISTORICAL_WORKFLOW_FILES = 76
HISTORICAL_WORKFLOW_REPLACEMENTS = 167
CRITICAL_CONTROL_PATHS = {
    '.github/workflows/verification-hardening-source-certification.yml',
    'scripts/ga/verify_repository_workflow_pin_refresh.py',
    'scripts/ga/certify_verification_hardening_maintenance.py',
    'scripts/ga/certify_verification_hardening_source.py',
    'scripts/ga/certify_verification_hardening_source_with_pin_refresh.py',
    'scripts/ga/_certify_verification_hardening_source_impl.py',
    'scripts/ga/verify_verification_hardening_action_lock.py',
    'scripts/ga/verify_verification_hardening_workflow_policy.py',
    'scripts/ga/verify_verification_hardening_checkout_policy.py',
    'scripts/ga/verify_verification_hardening_event_head_policy.py',
    'scripts/ga/verify_repository_workflow_action_policy.py',
    'scripts/ga/scan_repository_private_material.py',
}
COMPANION_TEST_PREFIXES = (
    'tests/test_verification_hardening',
    'tests/test_repository_policy',
)


class VerificationMaintenanceError(RuntimeError):
    pass


def _git(root: Path, *args: str, check: bool = True) -> bytes:
    completed = subprocess.run(
        ['git', '-C', str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if check and completed.returncode != 0:
        raise VerificationMaintenanceError(
            f"git {' '.join(args)} failed: {completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def _exact_commit(value: str, label: str) -> str:
    text = str(value or '').strip().lower()
    if len(text) != 40 or any(ch not in '0123456789abcdef' for ch in text):
        raise VerificationMaintenanceError(f'{label} must be an exact lowercase 40-hex commit')
    return text


def _paths(raw: bytes) -> list[str]:
    try:
        values = [item for item in raw.decode('utf-8').split('\x00') if item]
    except UnicodeDecodeError as exc:
        raise VerificationMaintenanceError('git returned a non-UTF-8 path') from exc
    if any(any(ch in value for ch in ('\n', '\r', '\t', '\x00')) for value in values):
        raise VerificationMaintenanceError('maintenance delta contains an unsupported path character')
    return values


def _read_json(path: Path, label: str) -> dict[str, Any]:
    candidate = path.expanduser().resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise VerificationMaintenanceError(f'{label} is missing or unsafe')
    try:
        value = json.loads(candidate.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        raise VerificationMaintenanceError(f'{label} is invalid JSON') from exc
    if not isinstance(value, dict):
        raise VerificationMaintenanceError(f'{label} root must be an object')
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _load_scanner():
    spec = importlib.util.spec_from_file_location('psmatrix_maintenance_private_scanner', SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise VerificationMaintenanceError('unable to load repository private-material scanner')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_historical_pin_receipt(receipt: dict[str, Any], candidate: str) -> None:
    expected = {
        'schema': 1,
        'kind': 'psmatrix.repository-workflow-action-pin-refresh-certification',
        'version': '2.0.0',
        'status': 'PASS',
        'baseline_commit': HISTORICAL_PIN_BASELINE,
        'certified_head': HISTORICAL_PIN_CANDIDATE,
        'workflow_file_count': HISTORICAL_WORKFLOW_FILES,
        'workflow_replacement_count': HISTORICAL_WORKFLOW_REPLACEMENTS,
        'historical_candidate_additions_allowed': True,
        'historical_candidate_additions_outside_pin_proof': True,
        'baseline_files_deleted': 0,
        'baseline_modifications_outside_certified_pin_refresh': 0,
        'pin_only_transform_verified': True,
        'pin_only_transform_verified_for_baseline_modifications': True,
        'ga_eligible': False,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise VerificationMaintenanceError(f'historical pin-refresh receipt mismatch: {key}')
    added_count = receipt.get('baseline_files_added')
    if isinstance(added_count, bool) or not isinstance(added_count, int) or added_count <= 0:
        raise VerificationMaintenanceError('historical pin-refresh added-path count is invalid')
    added_digest = str(receipt.get('added_paths_sha256') or '')
    if re.fullmatch(r'[0-9a-f]{64}', added_digest) is None:
        raise VerificationMaintenanceError('historical pin-refresh added-path manifest digest is invalid')
    if receipt.get('repository_head') != candidate:
        raise VerificationMaintenanceError('historical pin-refresh receipt is not bound to current candidate HEAD')
    if receipt.get('historical_candidate_ancestor_of_repository_head') is not True:
        raise VerificationMaintenanceError('historical pin-refresh candidate ancestry was not verified')
    replacement_map = receipt.get('replacement_map')
    if not isinstance(replacement_map, dict) or len(replacement_map) != 2:
        raise VerificationMaintenanceError('historical pin-refresh replacement map is malformed')
    files = receipt.get('files')
    if not isinstance(files, list) or len(files) != int(receipt.get('file_count') or -1):
        raise VerificationMaintenanceError('historical pin-refresh file manifest is malformed')


def _verify_private_scan(root: Path, receipt: dict[str, Any], candidate: str) -> str:
    for key, value in {
        'schema': 1,
        'kind': 'psmatrix.repository-private-material-scan',
        'version': '2.0.0',
        'status': 'PASS',
        'finding_count': 0,
        'secret_values_emitted': False,
        'secret_hashes_emitted': False,
        'secret_lengths_emitted': False,
        'tracked_blob_authority_verified': True,
        'working_tree_clean_verified': True,
        'repository_head_stable_during_scan': True,
        'repository_tree_stable_during_scan': True,
        'expected_repository_head_verified': True,
        'ga_eligible': False,
    }.items():
        if receipt.get(key) != value:
            raise VerificationMaintenanceError(f'private-material scan receipt mismatch: {key}')
    if receipt.get('repository_head') != candidate or receipt.get('expected_repository_head') != candidate:
        raise VerificationMaintenanceError('private-material scan is not bound to current candidate HEAD')
    tree = _exact_commit(str(receipt.get('repository_tree') or ''), 'private-material repository tree')
    expected_tree = _exact_commit(_git(root, 'rev-parse', f'{candidate}^{{tree}}').decode('ascii').strip(), 'candidate tree')
    if tree != expected_tree:
        raise VerificationMaintenanceError('private-material scan repository tree differs from candidate tree')
    if _git(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise VerificationMaintenanceError('maintenance certification requires a clean working tree')
    scanner = _load_scanner()
    fresh = scanner.scan_git_head(root, 'git', candidate)
    for key in (
        'schema', 'kind', 'version', 'status', 'tracked_file_count', 'finding_count', 'findings',
        'scanned_classes', 'secret_values_emitted', 'secret_hashes_emitted', 'secret_lengths_emitted',
        'tracked_blob_authority_verified', 'ga_eligible',
    ):
        if fresh.get(key) != receipt.get(key):
            raise VerificationMaintenanceError(f'private-material independent re-scan mismatch: {key}')
    return tree


def _critical_changes_require_tests(changed: list[str], deleted: set[str]) -> None:
    critical = sorted(path for path in changed if path in CRITICAL_CONTROL_PATHS)
    if not critical:
        return
    if any(path in deleted for path in critical):
        raise VerificationMaintenanceError(
            'verification-maintenance critical control may not be deleted: ' + ','.join(path for path in critical if path in deleted)
        )
    tests = [path for path in changed if any(path.startswith(prefix) for prefix in COMPANION_TEST_PREFIXES)]
    if not tests:
        raise VerificationMaintenanceError(
            'verification-maintenance critical control changed without companion verification-hardening test coverage: '
            + ','.join(critical)
        )


def certify(
    root: Path,
    base: str,
    candidate: str,
    historical_pin: dict[str, Any],
    private_scan: dict[str, Any],
) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise VerificationMaintenanceError('repository root is missing')
    base = _exact_commit(base, 'maintenance base')
    candidate = _exact_commit(candidate, 'maintenance candidate')
    head = _exact_commit(_git(root, 'rev-parse', 'HEAD').decode('ascii').strip(), 'repository HEAD')
    if candidate != head:
        raise VerificationMaintenanceError('maintenance candidate differs from exact checked-out HEAD')
    _git(root, 'cat-file', '-e', f'{base}^{{commit}}')
    _git(root, 'cat-file', '-e', f'{candidate}^{{commit}}')
    _git(root, 'merge-base', '--is-ancestor', base, candidate)
    if base == candidate:
        raise VerificationMaintenanceError('maintenance certification requires a nonempty base-to-candidate range')
    _git(root, 'merge-base', '--is-ancestor', HISTORICAL_PIN_CANDIDATE, candidate)

    changed = _paths(_git(root, 'diff', '--name-only', '-z', f'{base}..{candidate}'))
    if not changed:
        raise VerificationMaintenanceError('maintenance delta is empty')
    runtime = sorted(path for path in changed if path.startswith('src/psmatrix/'))
    if runtime:
        raise VerificationMaintenanceError(
            'verification-maintenance certification may not certify runtime product source changes: ' + ','.join(runtime)
        )
    deleted = set(_paths(_git(root, 'diff', '--diff-filter=D', '--name-only', '-z', f'{base}..{candidate}')))
    _critical_changes_require_tests(changed, deleted)
    _verify_historical_pin_receipt(historical_pin, candidate)
    tree = _verify_private_scan(root, private_scan, candidate)

    files: list[dict[str, Any]] = []
    for relative in sorted(changed):
        if relative in deleted:
            files.append({'path': relative, 'state': 'deleted'})
            continue
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise VerificationMaintenanceError(f'changed path escapes repository: {relative}') from exc
        if not path.is_file() or path.is_symlink():
            raise VerificationMaintenanceError(f'changed path is missing or unsafe: {relative}')
        files.append({'path': relative, 'state': 'present', 'sha256': _sha256(path), 'size': path.stat().st_size})

    return {
        'schema': 1,
        'kind': 'psmatrix.verification-hardening-maintenance-certification',
        'version': '2.0.0',
        'status': 'PASS',
        'maintenance_base': base,
        'certified_head': candidate,
        'certified_tree': tree,
        'historical_pin_refresh': {
            'baseline_commit': HISTORICAL_PIN_BASELINE,
            'candidate_commit': HISTORICAL_PIN_CANDIDATE,
            'workflow_file_count': HISTORICAL_WORKFLOW_FILES,
            'workflow_replacement_count': HISTORICAL_WORKFLOW_REPLACEMENTS,
            'added_path_count': historical_pin['baseline_files_added'],
            'added_paths_sha256': historical_pin['added_paths_sha256'],
            'additions_outside_pin_proof': True,
            'pin_only_transform_verified_for_baseline_modifications': True,
            'candidate_ancestor_of_certified_head': True,
        },
        'private_material_scan': {
            'status': 'PASS',
            'finding_count': 0,
            'repository_head': candidate,
            'repository_tree': tree,
            'independently_reverified': True,
        },
        'delta_file_count': len(files),
        'runtime_source_changes': 0,
        'critical_control_changes': sorted(path for path in changed if path in CRITICAL_CONTROL_PATHS),
        'files': files,
        'boundaries': {
            'current_base_to_candidate_only': True,
            'historical_publication_proof_separate': True,
            'historical_additions_outside_pin_proof': True,
            'runtime_product_source_certified': False,
            'private_material_findings': 0,
            'production_state_mutated': False,
            'production_readiness_claimed': False,
            'final_ga_evaluator_invoked': False,
            'ga_eligible': False,
        },
        'ga_eligible': False,
    }


def _write_output(path: Path, value: dict[str, Any]) -> None:
    absolute = path.expanduser().absolute()
    if absolute.exists() or absolute.is_symlink():
        raise VerificationMaintenanceError('maintenance certification output must not already exist')
    parent = absolute.parent.resolve()
    if not parent.is_dir():
        raise VerificationMaintenanceError('maintenance certification output parent must already exist')
    candidate = parent / absolute.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_BINARY'):
        flags |= os.O_BINARY
    fd = os.open(candidate, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise VerificationMaintenanceError('maintenance certification output is not a regular file')
        payload = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')
        written = os.write(fd, payload)
        if written != len(payload):
            raise VerificationMaintenanceError('maintenance certification output write was incomplete')
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description='Certify current-base PSMatrix verification-hardening maintenance while preserving the immutable historical publication proof')
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--base', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--historical-workflow-pin-refresh', type=Path, required=True)
    parser.add_argument('--private-scan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        historical = _read_json(args.historical_workflow_pin_refresh, 'historical workflow pin-refresh receipt')
        private_scan = _read_json(args.private_scan, 'private-material scan receipt')
        value = certify(args.root, args.base, args.candidate, historical, private_scan)
        _write_output(args.output, value)
        print(f"verification_hardening_maintenance=PASS files={value['delta_file_count']}")
        print(f"maintenance_base={value['maintenance_base']}")
        print(f"certified_head={value['certified_head']}")
        print('historical_publication_proof_separate=true')
        print('historical_pin_refresh_verified=true')
        print('historical_additions_outside_pin_proof=true')
        print('private_material_scan_independently_reverified=true')
        print('runtime_source_changes=0')
        print('production_state_mutated=false')
        print('ga_eligible=false')
        return 0
    except (OSError, TypeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError, VerificationMaintenanceError) as exc:
        print(f'verification hardening maintenance certification failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
