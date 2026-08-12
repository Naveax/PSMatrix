from __future__ import annotations

import argparse
import sys
from pathlib import Path

WORKFLOW_DIR = Path('.github/workflows')
PIN_REPLACEMENTS = {
    '34e114876b0b11c390a56381ad16ebd13914f8d5': '11d5960a326750d5838078e36cf38b85af677262',
    'a309ff8b426b58ec0e2a45f0f869d46889d02405': 'ece7cb06caefa5fff74198d8649806c4678c61a1',
}


class WorkflowPinRefreshError(RuntimeError):
    pass


def workflow_paths(root: Path) -> list[Path]:
    directory = root / WORKFLOW_DIR
    if not directory.is_dir():
        raise WorkflowPinRefreshError('workflow directory is missing')
    return sorted([*directory.glob('*.yml'), *directory.glob('*.yaml')])


def refresh(root: Path, *, apply: bool) -> dict[str, object]:
    root = root.resolve()
    files_changed = 0
    replacements = 0
    per_file: dict[str, int] = {}
    remaining: list[str] = []

    for path in workflow_paths(root):
        original = path.read_text(encoding='utf-8')
        updated = original
        count = 0
        for old, new in PIN_REPLACEMENTS.items():
            hits = updated.count(old)
            if hits:
                updated = updated.replace(old, new)
                count += hits
        if count:
            files_changed += 1
            replacements += count
            per_file[path.relative_to(root).as_posix()] = count
            if apply:
                path.write_text(updated, encoding='utf-8', newline='')
        check_text = updated if apply else original
        for old in PIN_REPLACEMENTS:
            if old in check_text:
                remaining.append(f'{path.relative_to(root).as_posix()}:{old}')

    return {
        'files_changed': files_changed,
        'replacements': replacements,
        'per_file': per_file,
        'remaining': sorted(remaining),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Refresh repository workflow action pins deterministically')
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        result = refresh(args.root, apply=args.apply)
        for path, count in result['per_file'].items():
            print(f'workflow_pin_refresh path={path} replacements={count}')
        print(f"files_changed={result['files_changed']}")
        print(f"replacements={result['replacements']}")
        if args.apply:
            remaining = result['remaining']
            if remaining:
                raise WorkflowPinRefreshError('old workflow pins remain after apply: ' + ', '.join(remaining))
            print('workflow_pin_refresh=PASS')
            return 0
        if result['files_changed']:
            print('workflow_pin_refresh=NEEDED', file=sys.stderr)
            return 1
        print('workflow_pin_refresh=PASS')
        return 0
    except (OSError, TypeError, ValueError, WorkflowPinRefreshError) as exc:
        print(f'workflow pin refresh failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
