from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = '3ffc6b6d7cd58d64224f780aa819b50f50f72491'
PIN_REPLACEMENTS = {
    '34e114876b0b11c390a56381ad16ebd13914f8d5': '11d5960a326750d5838078e36cf38b85af677262',
    'a309ff8b426b58ec0e2a45f0f869d46889d02405': 'ece7cb06caefa5fff74198d8649806c4678c61a1',
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


def _paths(raw: bytes) -> list[str]:
    try:
        values = [item for item in raw.decode('utf-8').split('\x00') if item]
    except UnicodeDecodeError as exc:
        raise RepositoryWorkflowPinRefreshError('git returned non-UTF-8 path data') from exc
    if any(any(ch in path for ch in ('\n', '\r', '\t')) for path in values):
        raise RepositoryWorkflowPinRefreshError('workflow refresh contains unsupported path characters')
    return values


def _is_workflow(path: str) -> bool:
    return path.startswith('.github/workflows/') and (path.endswith('.yml') or path.endswith('.yaml'))


def _blob(root: Path, revision: str, path: str) -> bytes:
    return _git(root, 'show', f'{revision}:{path}')


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(
    root: Path,
    baseline: str,
    *,
    expected_files: int | None = None,
    expected_replacements: int | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise RepositoryWorkflowPinRefreshError('repository root is missing')
    if len(baseline) != 40 or any(ch not in '0123456789abcdef' for ch in baseline):
        raise RepositoryWorkflowPinRefreshError('baseline must be exact lowercase 40-hex')
    _git(root, 'merge-base', '--is-ancestor', baseline, 'HEAD')
    head = _git(root, 'rev-parse', 'HEAD').decode('ascii').strip().lower()
    if len(head) != 40 or any(ch not in '0123456789abcdef' for ch in head):
        raise RepositoryWorkflowPinRefreshError('unable to resolve exact HEAD')

    deleted = _paths(_git(root, 'diff', '--diff-filter=D', '--name-only', '-z', f'{baseline}..HEAD'))
    if deleted:
        raise RepositoryWorkflowPinRefreshError(
            'workflow pin refresh may not delete baseline paths: ' + ','.join(sorted(deleted))
        )
    modified = _paths(_git(root, 'diff', '--diff-filter=M', '--name-only', '-z', f'{baseline}..HEAD'))
    non_workflow = sorted(path for path in modified if not _is_workflow(path))
    if non_workflow:
        raise RepositoryWorkflowPinRefreshError(
            'non-workflow baseline modifications are forbidden: ' + ','.join(non_workflow)
        )
    if not modified:
        raise RepositoryWorkflowPinRefreshError('no baseline workflow pin refresh was found')

    total_replacements = 0
    manifest: list[dict[str, Any]] = []
    for path in sorted(modified):
        before = _blob(root, baseline, path)
        after = _blob(root, head, path)
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
                f'baseline workflow modification contains no approved pin replacement: {path}'
            )
        if transformed != after:
            raise RepositoryWorkflowPinRefreshError(
                f'workflow differs from exact approved pin-only transformation: {path}'
            )
        for old in PIN_REPLACEMENTS:
            if old.encode('ascii') in after:
                raise RepositoryWorkflowPinRefreshError(f'old action pin remains after refresh: {path}')
        total_replacements += replacements
        manifest.append(
            {
                'path': path,
                'replacements': replacements,
                'baseline_sha256': _sha256(before),
                'baseline_bytes': len(before),
                'current_sha256': _sha256(after),
                'current_bytes': len(after),
            }
        )

    if expected_files is not None and len(manifest) != expected_files:
        raise RepositoryWorkflowPinRefreshError(
            f'workflow pin refresh file count mismatch: expected {expected_files}, got {len(manifest)}'
        )
    if expected_replacements is not None and total_replacements != expected_replacements:
        raise RepositoryWorkflowPinRefreshError(
            f'workflow pin refresh replacement count mismatch: expected {expected_replacements}, got {total_replacements}'
        )

    return {
        'schema': 1,
        'kind': 'psmatrix.repository-workflow-action-pin-refresh-certification',
        'version': '2.0.0',
        'status': 'PASS',
        'baseline_commit': baseline,
        'certified_head': head,
        'replacement_map': dict(PIN_REPLACEMENTS),
        'file_count': len(manifest),
        'replacement_count': total_replacements,
        'modified_workflow_paths': [item['path'] for item in manifest],
        'files': manifest,
        'baseline_files_deleted': 0,
        'non_workflow_baseline_modifications': 0,
        'pin_only_transform_verified': True,
        'ga_eligible': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Certify exact repository workflow action-pin-only refresh')
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--expected-files', type=int)
    parser.add_argument('--expected-replacements', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(
            args.root,
            args.baseline,
            expected_files=args.expected_files,
            expected_replacements=args.expected_replacements,
        )
        output = args.output.expanduser().resolve()
        if output.exists():
            raise RepositoryWorkflowPinRefreshError('output must not already exist')
        if not output.parent.is_dir():
            raise RepositoryWorkflowPinRefreshError('output parent must already exist')
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print(f"repository_workflow_pin_refresh=PASS files={value['file_count']} replacements={value['replacement_count']}")
        print(f"baseline={value['baseline_commit']}")
        print(f"certified_head={value['certified_head']}")
        print('pin_only_transform_verified=true')
        print('ga_eligible=false')
        return 0
    except (OSError, TypeError, ValueError, subprocess.SubprocessError, RepositoryWorkflowPinRefreshError) as exc:
        print(f'repository workflow pin refresh certification failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
