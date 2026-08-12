from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WORKFLOWS = (
    Path(".github/workflows/ga-repository-private-material-scan.yml"),
    Path(".github/workflows/verification-hardening-source-certification.yml"),
    Path(".github/workflows/powershell-source-parse-diagnostic.yml"),
)
PERMISSIONS_KEY = re.compile(r"(?:^|\s)(?:[\"']?permissions[\"']?)\s*:")
PULL_REQUEST_TARGET_KEY = re.compile(r"(?:^|\s)(?:[\"']?pull_request_target[\"']?)\s*:")


class VerificationHardeningWorkflowPolicyError(RuntimeError):
    pass


def _top_level_permissions(lines: list[str], label: str) -> list[str]:
    permission_keys: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        code = line.split("#", 1)[0].rstrip()
        if PERMISSIONS_KEY.search(code) is not None:
            permission_keys.append((index, code))
    if len(permission_keys) != 1:
        raise VerificationHardeningWorkflowPolicyError(
            f"{label} must define exactly one permissions key"
        )
    index, code = permission_keys[0]
    if code != "permissions:":
        raise VerificationHardeningWorkflowPolicyError(
            f"{label} permissions key must use canonical top-level block syntax"
        )
    entries: list[str] = []
    for line in lines[index + 1 :]:
        if not line.strip():
            continue
        if not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    "):
            entries.append(line.strip())
    return entries


def verify(root: Path) -> dict[str, object]:
    root = root.resolve()
    if not root.is_dir():
        raise VerificationHardeningWorkflowPolicyError("repository root is missing")
    for relative in WORKFLOWS:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise VerificationHardeningWorkflowPolicyError(
                f"required hardening workflow is missing: {relative.as_posix()}"
            ) from exc
        lines = text.splitlines()
        for line in lines:
            code = line.split("#", 1)[0].strip()
            if PULL_REQUEST_TARGET_KEY.search(code) is not None:
                raise VerificationHardeningWorkflowPolicyError(
                    f"pull_request_target is forbidden in any key syntax: {relative.as_posix()}"
                )
            if code in {"write-all", "read-all", "permissions: write-all", "permissions: read-all"}:
                raise VerificationHardeningWorkflowPolicyError(
                    f"broad workflow permission is forbidden: {relative.as_posix()}"
                )
        permissions = _top_level_permissions(lines, relative.as_posix())
        if permissions != ["contents: read"]:
            raise VerificationHardeningWorkflowPolicyError(
                f"workflow permissions must be exactly contents: read: {relative.as_posix()}"
            )
    return {
        "schema": 1,
        "kind": "psmatrix.verification-hardening-workflow-privilege-policy",
        "version": "2.0.0",
        "status": "PASS",
        "workflow_count": len(WORKFLOWS),
        "pull_request_target_workflows": 0,
        "broad_permission_workflows": 0,
        "job_level_permission_blocks": 0,
        "non_read_only_workflows": 0,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify read-only trigger and permission policy for verification-hardening workflows"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        value = verify(args.root)
        print(f"verification_hardening_workflow_privilege_policy=PASS workflows={value['workflow_count']}")
        print("pull_request_target_workflows=0")
        print("broad_permission_workflows=0")
        print("job_level_permission_blocks=0")
        print("non_read_only_workflows=0")
        print("ga_eligible=false")
        return 0
    except (OSError, TypeError, ValueError, VerificationHardeningWorkflowPolicyError) as exc:
        print(f"verification hardening workflow privilege policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
