from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path('.github/workflows')
USE_KEY = re.compile(r'(?:^|[\s{,])(?:[\"\']?uses[\"\']?)\s*:')
CANONICAL_USE = re.compile(
    r'^\s*(?:-\s+)?uses:\s*(?P<target>[^\s#]+)(?:\s+#.*)?$'
)
HEX40 = re.compile(r'^[0-9a-f]{40}$')
ACTION_NAME = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@/-]+)?$')

APPROVED_CURRENT: dict[str, set[str]] = {
    'actions/checkout': {'11d5960a326750d5838078e36cf38b85af677262'},
    'actions/setup-python': {
        'a26af69be951a213d495a4c3e4e4022e16d87065',  # v5
        'ece7cb06caefa5fff74198d8649806c4678c61a1',  # v6
    },
    'actions/upload-artifact': {'ea165f8d65b6e75b540449e92b4886f43607fa02'},
    'actions/download-artifact': {'d3f86a106a0bac45b974a628896c90dbdf5c8093'},
}


class RepositoryWorkflowActionPolicyError(RuntimeError):
    pass


def _workflow_paths(root: Path) -> list[Path]:
    directory = root / WORKFLOW_DIR
    if not directory.is_dir():
        raise RepositoryWorkflowActionPolicyError('workflow directory is missing')
    paths = sorted([*directory.glob('*.yml'), *directory.glob('*.yaml')])
    if not paths:
        raise RepositoryWorkflowActionPolicyError('no workflow files found')
    return paths


def inspect(root: Path) -> dict[str, object]:
    root = root.resolve()
    violations: list[str] = []
    observed: dict[str, set[str]] = {}
    external_refs = 0
    local_refs = 0

    for path in _workflow_paths(root):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding='utf-8')
        for line_number, line in enumerate(text.splitlines(), start=1):
            if USE_KEY.search(line) is None:
                continue
            match = CANONICAL_USE.fullmatch(line)
            if match is None:
                violations.append(f'{relative}:{line_number}: noncanonical uses syntax')
                continue
            target = match.group('target')
            if target.startswith('./'):
                local_refs += 1
                continue
            if target.startswith('docker://'):
                violations.append(f'{relative}:{line_number}: docker action refs are not permitted by repository policy')
                continue
            if '@' not in target:
                violations.append(f'{relative}:{line_number}: external action ref is missing @sha')
                continue
            action, ref = target.rsplit('@', 1)
            if ACTION_NAME.fullmatch(action) is None:
                violations.append(f'{relative}:{line_number}: unsupported external action target {action!r}')
                continue
            root_action = '/'.join(action.split('/')[:2])
            external_refs += 1
            observed.setdefault(root_action, set()).add(ref)
            if HEX40.fullmatch(ref) is None:
                violations.append(f'{relative}:{line_number}: mutable/non-40hex action ref {target}')
                continue
            approved = APPROVED_CURRENT.get(root_action)
            if approved is not None and ref not in approved:
                violations.append(f'{relative}:{line_number}: outdated approved action pin {target}')

    return {
        'workflow_count': len(_workflow_paths(root)),
        'external_refs': external_refs,
        'local_refs': local_refs,
        'observed': {key: sorted(value) for key, value in sorted(observed.items())},
        'violations': violations,
    }


def verify(root: Path) -> dict[str, object]:
    result = inspect(root)
    violations = result['violations']
    assert isinstance(violations, list)
    if violations:
        raise RepositoryWorkflowActionPolicyError('\n'.join(str(item) for item in violations))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description='Verify immutable repository-wide GitHub Actions references')
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--inventory', action='store_true')
    args = parser.parse_args()
    try:
        result = inspect(args.root) if args.inventory else verify(args.root)
        for action, refs in result['observed'].items():
            print(f'action={action} refs={",".join(refs)}')
        print(f"workflow_count={result['workflow_count']}")
        print(f"external_action_refs={result['external_refs']}")
        print(f"local_action_refs={result['local_refs']}")
        violations = result['violations']
        if violations:
            print(f'workflow_action_policy=FAIL violations={len(violations)}', file=sys.stderr)
            for item in violations:
                print(f'VIOLATION {item}', file=sys.stderr)
            return 1
        print('workflow_action_policy=PASS')
        print('ga_eligible=false')
        return 0
    except (OSError, TypeError, ValueError, RepositoryWorkflowActionPolicyError) as exc:
        print(f'repository workflow action policy failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
