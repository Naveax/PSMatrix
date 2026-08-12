from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

LOCK_PATH = Path("scripts/ga/verification-hardening-action-lock.json")
WORKFLOWS = (
    Path(".github/workflows/ga-repository-private-material-scan.yml"),
    Path(".github/workflows/verification-hardening-source-certification.yml"),
    Path(".github/workflows/powershell-source-parse-diagnostic.yml"),
)
USE_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?P<commit>[0-9a-f]{40})(?:\s+#.*)?$"
)
USE_KEY = re.compile(r"(?:^|[\s{,])(?:[\"']?uses[\"']?)\s*:")


class VerificationHardeningActionLockError(RuntimeError):
    pass


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationHardeningActionLockError(
            f"action lock is missing or invalid: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise VerificationHardeningActionLockError("action lock root must be object")
    return value


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise VerificationHardeningActionLockError("repository root is missing")
    lock = _load_json_object(root / LOCK_PATH)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.verification-hardening-action-lock":
        raise VerificationHardeningActionLockError("action lock schema/kind is invalid")
    actions = lock.get("actions")
    if not isinstance(actions, dict) or not actions:
        raise VerificationHardeningActionLockError("action lock actions map is missing")

    expected: dict[str, str] = {}
    for action, entry in actions.items():
        if not isinstance(action, str) or not isinstance(entry, dict):
            raise VerificationHardeningActionLockError("action lock entry is invalid")
        commit = entry.get("commit")
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise VerificationHardeningActionLockError(
                f"action lock commit is invalid for {action}"
            )
        expected[action] = commit

    observed: dict[str, set[str]] = {action: set() for action in expected}
    checked_uses = 0
    for relative in WORKFLOWS:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise VerificationHardeningActionLockError(
                f"required hardening workflow is missing: {relative.as_posix()}"
            ) from exc
        for line_number, line in enumerate(text.splitlines(), start=1):
            if USE_KEY.search(line) is None:
                continue
            match = USE_LINE.fullmatch(line)
            if match is None:
                raise VerificationHardeningActionLockError(
                    f"workflow action reference must use canonical immutable uses syntax: {relative.as_posix()}:{line_number}"
                )
            action = match.group("action")
            commit = match.group("commit")
            if action not in expected:
                raise VerificationHardeningActionLockError(
                    f"workflow uses action absent from lock: {action}"
                )
            if commit != expected[action]:
                raise VerificationHardeningActionLockError(
                    f"workflow action SHA differs from lock: {action}"
                )
            observed[action].add(relative.as_posix())
            checked_uses += 1

    missing = sorted(action for action, paths in observed.items() if not paths)
    if missing:
        raise VerificationHardeningActionLockError(
            "locked actions are not referenced by hardening workflows: " + ", ".join(missing)
        )
    return {
        "schema": 1,
        "kind": "psmatrix.verification-hardening-action-lock-verification",
        "version": "2.0.0",
        "status": "PASS",
        "workflow_count": len(WORKFLOWS),
        "locked_action_count": len(expected),
        "checked_uses_count": checked_uses,
        "mutable_action_refs": 0,
        "unlocked_actions": 0,
        "action_sha_mismatches": 0,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify immutable action pins in PSMatrix verification-hardening workflows"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        value = verify(args.root)
        print(
            "verification_hardening_action_lock=PASS "
            f"workflows={value['workflow_count']} actions={value['locked_action_count']} uses={value['checked_uses_count']}"
        )
        print("mutable_action_refs=0")
        print("unlocked_actions=0")
        print("action_sha_mismatches=0")
        print("ga_eligible=false")
        return 0
    except (OSError, TypeError, ValueError, VerificationHardeningActionLockError) as exc:
        print(f"verification hardening action lock failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
