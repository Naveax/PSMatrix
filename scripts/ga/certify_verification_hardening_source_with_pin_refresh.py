from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
LEGACY_PATH = Path(__file__).with_name('certify_verification_hardening_source.py')
PIN_REFRESH_PATH = Path(__file__).with_name('verify_repository_workflow_pin_refresh.py')
DEFAULT_BASELINE = '3ffc6b6d7cd58d64224f780aa819b50f50f72491'
DEFAULT_EXPECTED_FILES = 76
DEFAULT_EXPECTED_REPLACEMENTS = 167


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'unable to load {path.name}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = _load(LEGACY_PATH, 'psmatrix_legacy_hardening_source_certifier')
pin_refresh = _load(PIN_REFRESH_PATH, 'psmatrix_workflow_pin_refresh_certifier')
HardeningSourceCertificationError = legacy.HardeningSourceCertificationError


def _verify_pin_refresh_receipt(
    root: Path,
    baseline: str,
    supplied: dict[str, Any],
    *,
    expected_files: int,
    expected_replacements: int,
) -> dict[str, Any]:
    try:
        fresh = pin_refresh.verify(
            root,
            baseline,
            expected_files=expected_files,
            expected_replacements=expected_replacements,
        )
    except Exception as exc:
        raise HardeningSourceCertificationError(
            f'independent workflow pin-refresh revalidation failed: {exc}'
        ) from exc
    if fresh != supplied:
        raise HardeningSourceCertificationError(
            'supplied workflow pin-refresh receipt differs from independent exact Git-object revalidation'
        )
    return fresh


def _filter_non_additive_git(original_git, certified_paths: set[str]):
    def wrapped(root: Path, *args: str) -> bytes:
        raw = original_git(root, *args)
        if args and args[0] == 'diff' and '--diff-filter=MDRCTUXB' in args:
            values = legacy._impl._paths(raw)
            remaining = [path for path in values if path not in certified_paths]
            return b''.join(path.encode('utf-8') + b'\x00' for path in remaining)
        return raw
    return wrapped


def certify(
    root: Path,
    baseline: str,
    private_scan: dict[str, Any],
    workflow_pin_refresh: dict[str, Any],
    *,
    expected_files: int = DEFAULT_EXPECTED_FILES,
    expected_replacements: int = DEFAULT_EXPECTED_REPLACEMENTS,
) -> dict[str, Any]:
    root = root.resolve()
    refresh = _verify_pin_refresh_receipt(
        root,
        baseline,
        workflow_pin_refresh,
        expected_files=expected_files,
        expected_replacements=expected_replacements,
    )
    certified_paths = set(refresh['modified_certified_paths'])
    if len(certified_paths) != refresh['file_count']:
        raise HardeningSourceCertificationError(
            'pin-refresh receipt contains duplicate modified paths'
        )

    impl = legacy._impl
    original_allowed = impl._allowed
    original_git = impl._git

    def allowed(path: str) -> bool:
        return path in certified_paths or original_allowed(path)

    impl._allowed = allowed
    impl._git = _filter_non_additive_git(original_git, certified_paths)
    try:
        value = legacy.certify(root, baseline, private_scan)
    finally:
        impl._allowed = original_allowed
        impl._git = original_git

    boundaries = value['boundaries']
    boundaries['additive_only'] = False
    boundaries['hardening_boundary_mode'] = 'ADDITIVE_PLUS_CERTIFIED_WORKFLOW_PIN_REFRESH'
    boundaries['certified_workflow_pin_refresh_only'] = True
    boundaries['baseline_files_modified'] = refresh['file_count']
    boundaries['baseline_files_modified_outside_certified_pin_refresh'] = 0
    boundaries['baseline_files_deleted'] = 0
    boundaries['workflow_pin_refresh_files'] = refresh['workflow_file_count']
    boundaries['workflow_pin_replacements'] = refresh['workflow_replacement_count']
    boundaries['pin_refresh_companion_files'] = refresh['companion_file_count']
    boundaries['pin_refresh_companion_replacements'] = refresh['companion_replacement_count']
    boundaries['certified_pin_refresh_files_total'] = refresh['file_count']
    boundaries['certified_pin_replacements_total'] = refresh['replacement_count']
    boundaries['workflow_pin_refresh_pin_only_transform_verified'] = True
    boundaries['runtime_source_changes'] = 0
    boundaries['ga_eligible'] = False

    value['hardening_boundary_mode'] = 'ADDITIVE_PLUS_CERTIFIED_WORKFLOW_PIN_REFRESH'
    value['workflow_pin_refresh_certification'] = {
        'kind': refresh['kind'],
        'baseline_commit': refresh['baseline_commit'],
        'certified_head': refresh['certified_head'],
        'workflow_file_count': refresh['workflow_file_count'],
        'workflow_replacement_count': refresh['workflow_replacement_count'],
        'companion_file_count': refresh['companion_file_count'],
        'companion_replacement_count': refresh['companion_replacement_count'],
        'file_count': refresh['file_count'],
        'replacement_count': refresh['replacement_count'],
        'pin_only_transform_verified': True,
        'independently_reverified': True,
    }
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Certify PSMatrix verification hardening with an independently certified workflow action-pin-only refresh'
    )
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--private-scan', type=Path, required=True)
    parser.add_argument('--workflow-pin-refresh', type=Path, required=True)
    parser.add_argument('--expected-workflow-pin-files', type=int, default=DEFAULT_EXPECTED_FILES)
    parser.add_argument('--expected-workflow-pin-replacements', type=int, default=DEFAULT_EXPECTED_REPLACEMENTS)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        private_scan = legacy._read_json_object(args.private_scan, 'private-material scan')
        refresh = legacy._read_json_object(args.workflow_pin_refresh, 'workflow pin-refresh certification')
        value = certify(
            args.root,
            args.baseline,
            private_scan,
            refresh,
            expected_files=args.expected_workflow_pin_files,
            expected_replacements=args.expected_workflow_pin_replacements,
        )
        legacy._write_source_certification_receipt(args.output, value)
        boundaries = value['boundaries']
        print(f"verification_hardening_source_certification=PASS files={value['delta_file_count']}")
        print(f"baseline={value['baseline_commit']}")
        print(f"certified_head={value['certified_head']}")
        print('hardening_boundary_mode=ADDITIVE_PLUS_CERTIFIED_WORKFLOW_PIN_REFRESH')
        print('additive_only=false')
        print('certified_workflow_pin_refresh_only=true')
        print(f"baseline_files_modified={boundaries['baseline_files_modified']}")
        print('baseline_files_modified_outside_certified_pin_refresh=0')
        print('baseline_files_deleted=0')
        print(f"workflow_pin_refresh_files={boundaries['workflow_pin_refresh_files']}")
        print(f"workflow_pin_replacements={boundaries['workflow_pin_replacements']}")
        print(f"pin_refresh_companion_files={boundaries['pin_refresh_companion_files']}")
        print(f"pin_refresh_companion_replacements={boundaries['pin_refresh_companion_replacements']}")
        print(f"certified_pin_refresh_files_total={boundaries['certified_pin_refresh_files_total']}")
        print(f"certified_pin_replacements_total={boundaries['certified_pin_replacements_total']}")
        print('workflow_pin_refresh_pin_only_transform_verified=true')
        print('private_material_scan_independently_reverified=true')
        print('runtime_source_changes=0')
        print('private_material_findings=0')
        print('production_state_mutated=false')
        print('ga_eligible=false')
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        HardeningSourceCertificationError,
        TypeError,
        ValueError,
    ) as exc:
        print(f'verification hardening source certification with workflow pin refresh failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
