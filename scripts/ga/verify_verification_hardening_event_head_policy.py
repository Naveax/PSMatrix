from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCANNER_WORKFLOW = Path(".github/workflows/ga-repository-private-material-scan.yml")
SOURCE_CERT_WORKFLOW = Path(".github/workflows/verification-hardening-source-certification.yml")
POWERSHELL_WORKFLOW = Path(".github/workflows/powershell-source-parse-diagnostic.yml")


class VerificationHardeningEventHeadPolicyError(RuntimeError):
    pass


def _read(root: Path, relative: Path) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError as exc:
        raise VerificationHardeningEventHeadPolicyError(
            f"required hardening workflow is missing: {relative.as_posix()}"
        ) from exc


def _step_block(text: str, name: str, label: str) -> str:
    lines = text.splitlines()
    marker = f"      - name: {name}"
    indices = [index for index, line in enumerate(lines) if line == marker]
    if len(indices) != 1:
        raise VerificationHardeningEventHeadPolicyError(
            f"{label} must define exactly one named step: {name}"
        )
    start = indices[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - name: "):
            end = index
            break
    return "\n".join(lines[start:end])


def _require_exact_once(text: str, token: str, label: str) -> None:
    count = text.count(token)
    if count != 1:
        raise VerificationHardeningEventHeadPolicyError(
            f"{label} must occur exactly once"
        )


def verify(root: Path) -> dict[str, object]:
    root = root.resolve()
    if not root.is_dir():
        raise VerificationHardeningEventHeadPolicyError("repository root is missing")

    scanner = _read(root, SCANNER_WORKFLOW)
    source_cert = _read(root, SOURCE_CERT_WORKFLOW)
    powershell = _read(root, POWERSHELL_WORKFLOW)

    scanner_step = _step_block(
        scanner,
        "Scan git-tracked repository for private material",
        SCANNER_WORKFLOW.as_posix(),
    )
    _require_exact_once(
        scanner_step,
        "python scripts/ga/scan_repository_private_material.py",
        "standalone scanner command",
    )
    _require_exact_once(
        scanner_step,
        '--expected-head "${GITHUB_SHA}"',
        "standalone scanner GITHUB_SHA binding",
    )

    source_scan_step = _step_block(
        source_cert,
        "Scan exact tracked tree for private material",
        SOURCE_CERT_WORKFLOW.as_posix(),
    )
    _require_exact_once(
        source_scan_step,
        "python scripts/ga/scan_repository_private_material.py",
        "source-cert scanner command",
    )
    _require_exact_once(
        source_scan_step,
        '--expected-head "$GITHUB_SHA"',
        "source-cert scanner GITHUB_SHA binding",
    )
    source_certify_step = _step_block(
        source_cert,
        "Certify additive-only verification hardening",
        SOURCE_CERT_WORKFLOW.as_posix(),
    )
    _require_exact_once(
        source_certify_step,
        "python scripts/ga/certify_verification_hardening_source.py",
        "source certification command",
    )
    if source_cert.index("- name: Scan exact tracked tree for private material") > source_cert.index(
        "- name: Certify additive-only verification hardening"
    ):
        raise VerificationHardeningEventHeadPolicyError(
            "source-cert private scan must execute before source certification"
        )

    powershell_verify_step = _step_block(
        powershell,
        "Verify exact workflow event revision",
        POWERSHELL_WORKFLOW.as_posix(),
    )
    for token in (
        'actual="$(git rev-parse HEAD)"',
        '[[ "$actual" != "$GITHUB_SHA" ]]',
        'echo "workflow_event_head_verified=true"',
    ):
        _require_exact_once(
            powershell_verify_step,
            token,
            f"PowerShell event-head token {token}",
        )
    positions = [
        powershell_verify_step.index('actual="$(git rev-parse HEAD)"'),
        powershell_verify_step.index('[[ "$actual" != "$GITHUB_SHA" ]]'),
        powershell_verify_step.index('echo "workflow_event_head_verified=true"'),
    ]
    if positions != sorted(positions):
        raise VerificationHardeningEventHeadPolicyError(
            "PowerShell event-head proof is out of order"
        )
    if powershell.index("- name: Verify exact workflow event revision") > powershell.index(
        "- name: Parse every tracked PowerShell script"
    ):
        raise VerificationHardeningEventHeadPolicyError(
            "PowerShell event-head verification must complete before parsing"
        )

    return {
        "schema": 1,
        "kind": "psmatrix.verification-hardening-event-head-policy",
        "version": "2.0.0",
        "status": "PASS",
        "workflow_count": 3,
        "scanner_event_head_bindings": 2,
        "powershell_event_head_preflights": 1,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify exact workflow-event HEAD binding in verification-hardening workflows"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        value = verify(args.root)
        print(f"verification_hardening_event_head_policy=PASS workflows={value['workflow_count']}")
        print(f"scanner_event_head_bindings={value['scanner_event_head_bindings']}")
        print(f"powershell_event_head_preflights={value['powershell_event_head_preflights']}")
        print("ga_eligible=false")
        return 0
    except (OSError, TypeError, ValueError, VerificationHardeningEventHeadPolicyError) as exc:
        print(f"verification hardening event-head policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
