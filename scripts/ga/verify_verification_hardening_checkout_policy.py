from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WORKFLOW_FETCH_DEPTH = {
    Path(".github/workflows/ga-repository-private-material-scan.yml"): "1",
    Path(".github/workflows/verification-hardening-source-certification.yml"): "0",
    Path(".github/workflows/powershell-source-parse-diagnostic.yml"): "1",
}
CHECKOUT = re.compile(
    r"^\s*(?:-\s+)?uses:\s*actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$"
)


class VerificationHardeningCheckoutPolicyError(RuntimeError):
    pass


def _checkout_step_block(text: str, label: str) -> list[str]:
    lines = text.splitlines()
    indices = [index for index, line in enumerate(lines) if CHECKOUT.fullmatch(line)]
    if len(indices) != 1:
        raise VerificationHardeningCheckoutPolicyError(
            f"{label} must contain exactly one immutable checkout step"
        )
    index = indices[0]
    block: list[str] = [lines[index]]
    for line in lines[index + 1 :]:
        if line.startswith("      - "):
            break
        block.append(line)
    return block


def verify(root: Path) -> dict[str, object]:
    root = root.resolve()
    if not root.is_dir():
        raise VerificationHardeningCheckoutPolicyError("repository root is missing")
    for relative, expected_depth in WORKFLOW_FETCH_DEPTH.items():
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise VerificationHardeningCheckoutPolicyError(
                f"required hardening workflow is missing: {relative.as_posix()}"
            ) from exc
        block = _checkout_step_block(text, relative.as_posix())
        normalized = [line.strip() for line in block if line.strip()]
        if "with:" not in normalized:
            raise VerificationHardeningCheckoutPolicyError(
                f"checkout step is missing with block: {relative.as_posix()}"
            )
        if "persist-credentials: false" not in normalized:
            raise VerificationHardeningCheckoutPolicyError(
                f"checkout must disable persisted credentials: {relative.as_posix()}"
            )
        expected = f"fetch-depth: {expected_depth}"
        if expected not in normalized:
            raise VerificationHardeningCheckoutPolicyError(
                f"checkout fetch-depth must be {expected_depth}: {relative.as_posix()}"
            )
        fetch_entries = [value for value in normalized if value.startswith("fetch-depth:")]
        if fetch_entries != [expected]:
            raise VerificationHardeningCheckoutPolicyError(
                f"checkout must define exactly one expected fetch-depth: {relative.as_posix()}"
            )
        credential_entries = [
            value for value in normalized if value.startswith("persist-credentials:")
        ]
        if credential_entries != ["persist-credentials: false"]:
            raise VerificationHardeningCheckoutPolicyError(
                f"checkout must define exactly one disabled credential persistence setting: {relative.as_posix()}"
            )
    return {
        "schema": 1,
        "kind": "psmatrix.verification-hardening-checkout-policy",
        "version": "2.0.0",
        "status": "PASS",
        "workflow_count": len(WORKFLOW_FETCH_DEPTH),
        "persist_credentials_false_count": len(WORKFLOW_FETCH_DEPTH),
        "fetch_depth_contract_count": len(WORKFLOW_FETCH_DEPTH),
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify checkout credential and ancestry policy for verification-hardening workflows"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        value = verify(args.root)
        print(f"verification_hardening_checkout_policy=PASS workflows={value['workflow_count']}")
        print(f"persist_credentials_false_count={value['persist_credentials_false_count']}")
        print(f"fetch_depth_contract_count={value['fetch_depth_contract_count']}")
        print("ga_eligible=false")
        return 0
    except (OSError, TypeError, ValueError, VerificationHardeningCheckoutPolicyError) as exc:
        print(f"verification hardening checkout policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
