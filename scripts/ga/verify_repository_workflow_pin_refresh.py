from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = '3ffc6b6d7cd58d64224f780aa819b50f50f72491'
HISTORICAL_CANDIDATE = '3b06770cb925add391f4552e5f1cbd0ed6aa96b5'
PIN_REPLACEMENTS = {
    '34e114876b0b11c390a56381ad16ebd13914f8d5': '11d5960a326750d5838078e36cf38b85af677262',
    'a309ff8b426b58ec0e2a45f0f869d46889d02405': 'ece7cb06caefa5fff74198d8649806c4678c61a1',
}
COMPANION_PIN_CONTRACT_PATHS = {
    'tests/test_final_vulnerability_scanner_supply_chain.py',
    'tests/test_windows_authority_self_hosted_rc3_staging.py',
}


class RepositoryWorkflowPinRefreshError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ['git', '-C', str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RepositoryWorkflowPinRefreshError(
            f"git {' '.join(args)} failed: {completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def _exact_commit(value: str, label: str) -> str:
    text = str(value or '').lower()
    if len(text) != 40 or any(ch not in '0123456789abcdef' for ch in text):
        raise RepositoryWorkflowPinRefreshError(f'{label} must be exact lowercase 40-hex')
    return text


def _paths(raw: bytes) -> list[str]:
    try:
        values = [item for item in raw.decode('utf-8').split('\x00') if item]
    except UnicodeDecodeError as exc:
        raise RepositoryWorkflowPinRefreshError('git returned non-UTF-8 path data') from exc
    if any(any(ch in path for ch in ('\n', '\r', '\t')) for path in values):
        raise RepositoryWorkflowPinRefreshError('pin refresh contains unsupported path characters')
    return values


def _is_workflow(path: str) -> bool:
    return path.startswith('.github/workflows/') and (path.endswith('.yml') or path.endswith('.yaml'))


def _is_certified_path(path: str) -> bool:
    return _is_workflow(path) or path in COMPANION_PIN_CONTRACT_PATHS


def _blob(root: Path, revision: str, path: str) -> bytes:
    return _git(root, 'show', f'{revision}:{path}')


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(
    root: Path,
    baseline: str,
    *,
    candidate: str | None = None,
    require_candidate_ancestor_of_head: bool = False,
    expected_files: int | None = None,
    expected_replacements: int | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise RepositoryWorkflowPinRefreshError('repository root is missing')
    baseline = _exact_commit(baseline, 'baseline')
    head = _exact_commit(_git(root, 'rev-parse', 'HEAD').decode('ascii').strip(), 'HEAD')
    certified = _exact_commit(candidate or head, 'candidate')
    _git(root, 'cat-file', '-e', f'{baseline}^{{commit}}')
    _git(root, 'cat-file', '-e', f'{certified}^{{commit}}')
    _git(root, 'merge-base', '--is-ancestor', baseline, certified)
    if certified == baseline:
        raise RepositoryWorkflowPinRefreshError('pin refresh candidate must differ from baseline')
    if require_candidate_ancestor_of_head:
        _git(root, 'merge-base', '--is-ancestor', certified, head)

    deleted = _paths(_git(root, 'diff', '--diff-filter=D', '--name-only', '-z', f'{baseline}..{certified}'))
    if deleted:
        raise RepositoryWorkflowPinRefreshError(
            'certified pin refresh may not delete baseline paths: ' + ','.join(sorted(deleted))
        )
    modified = _paths(_git(root, 'diff', '--diff-filter=M', '--name-only', '-z', f'{baseline}..{certified}'))
    forbidden = sorted(path for path in modified if not _is_certified_path(path))
    if forbidden:
        raise RepositoryWorkflowPinRefreshError(
            'baseline modifications escaped workflow/companion pin-refresh boundary: ' + ','.join(forbidden)
        )
    if not modified:
        raise RepositoryWorkflowPinRefreshError('no baseline pin refresh was found')

    total_replacements = 0
    workflow_replacements = 0
    companion_replacements = 0
    manifest: list[dict[str, Any]] = []
    for path in sorted(modified):
        before = _blob(root, baseline, path)
        after = _blob(root, certified, path)
        transformed = before
        replacements = 0
        for old, new in PIN_REPLACEMENTS.items():
            old_bytes = old.encode('ascii')
            new_bytes = new.encode('ascii')
            hits = transformed.count(old_bytes)
            if hits:
                transformed = transformed.replace(old_bytes, new_bytes)
                replacements += hits
        if replacements == 0:
            raise RepositoryWorkflowPinRefreshError(
                f'baseline modification contains no approved pin replacement: {path}'
            )
        if transformed != after:
            raise RepositoryWorkflowPinRefreshError(
                f'path differs from exact approved pin-only transformation: {path}'
            )
        for old in PIN_REPLACEMENTS:
            if old.encode('ascii') in after:
                raise RepositoryWorkflowPinRefreshError(f'old action pin remains after refresh: {path}')
        category = 'workflow' if _is_workflow(path) else 'companion-source-contract-test'
        total_replacements += replacements
        if category == 'workflow':
            workflow_replacements += replacements
        else:
            companion_replacements += replacements
        manifest.append(
            {
                'path': path,
                'category': category,
                'replacements': replacements,
                'baseline_sha256': _sha256(before),
                'baseline_bytes': len(before),
                'candidate_sha256': _sha256(after),
                'candidate_bytes': len(after),
            }
        )

    workflow_files = [item for item in manifest if item['category'] == 'workflow']
    companion_files = [item for item in manifest if item['category'] != 'workflow']
    if expected_files is not None and len(workflow_files) != expected_files:
        raise RepositoryWorkflowPinRefreshError(
            f'workflow pin refresh file count mismatch: expected {expected_files}, got {len(workflow_files)}'
        )
    if expected_replacements is not None and workflow_replacements != expected_replacements:
        raise RepositoryWorkflowPinRefreshError(
            f'workflow pin refresh replacement count mismatch: expected {expected_replacements}, got {workflow_replacements}'
        )

    return {
        'schema': 1,
        'kind': 'psmatrix.repository-workflow-action-pin-refresh-certification',
        'version': '2.0.0',
        'status': 'PASS',
        'baseline_commit': baseline,
        'certified_head': certified,
        'repository_head': head,
        'historical_candidate_ancestor_of_repository_head': (
            require_candidate_ancestor_of_head
        ),
        'replacement_map': dict(PIN_REPLACEMENTS),
        'file_count': len(manifest),
        'replacement_count': total_replacements,
        'workflow_file_count': len(workflow_files),
        'workflow_replacement_count': workflow_replacements,
        'companion_file_count': len(companion_files),
        'companion_replacement_count': companion_replacements,
        'modified_certified_paths': [item['path'] for item in manifest],
        'modified_workflow_paths': [item['path'] for item in workflow_files],
        'modified_companion_paths': [item['path'] for item in companion_files],
        'files': manifest,
        'baseline_files_deleted': 0,
        'baseline_modifications_outside_certified_pin_refresh': 0,
        'pin_only_transform_verified': True,
        'ga_eligible': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Certify an exact historical repository workflow/companion action-pin-only refresh')
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--candidate')
    parser.add_argument('--require-candidate-ancestor-of-head', action='store_true')
    parser.add_argument('--expected-files', type=int)
    parser.add_argument('--expected-replacements', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(
            args.root,
            args.baseline,
            candidate=args.candidate,
            require_candidate_ancestor_of_head=args.require_candidate_ancestor_of_head,
            expected_files=args.expected_files,
            expected_replacements=args.expected_replacements,
        )
        output = args.output.expanduser().resolve()
        if output.exists():
            raise RepositoryWorkflowPinRefreshError('output must not already exist')
        if not output.parent.is_dir():
            raise RepositoryWorkflowPinRefreshError('output parent must already exist')
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print(
            f"repository_workflow_pin_refresh=PASS workflow_files={value['workflow_file_count']} "
            f"workflow_replacements={value['workflow_replacement_count']} "
            f"companion_files={value['companion_file_count']} companion_replacements={value['companion_replacement_count']}"
        )
        print(f"certified_modified_files={value['file_count']}")
        print(f"certified_replacements={value['replacement_count']}")
        print(f"baseline={value['baseline_commit']}")
        print(f"certified_head={value['certified_head']}")
        print(f"repository_head={value['repository_head']}")
        print(f"historical_candidate_ancestor_of_repository_head={str(value['historical_candidate_ancestor_of_repository_head']).lower()}")
        print('pin_only_transform_verified=true')
        print('ga_eligible=false')
        return 0
    except (OSError, TypeError, ValueError, subprocess.SubprocessError, RepositoryWorkflowPinRefreshError) as exc:
        print(f'repository workflow pin refresh certification failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
