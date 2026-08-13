from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


class ReadinessSummaryVerificationError(RuntimeError):
    pass


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_symlink_components(path: Path, label: str) -> None:
    expanded = path.expanduser()
    parts = expanded.parts
    if expanded.is_absolute():
        current = Path(expanded.anchor)
        start = 1
    else:
        current = Path(".")
        start = 0
    for part in parts[start:]:
        current = current / part
        if current.is_symlink():
            raise ReadinessSummaryVerificationError(
                f"{label} may not traverse a symlink component"
            )


def _resolved_input(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ReadinessSummaryVerificationError(f"{label} is missing or unsafe")
    try:
        info = os.lstat(resolved)
    except OSError as exc:
        raise ReadinessSummaryVerificationError(
            f"{label} could not be inspected: {exc}"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ReadinessSummaryVerificationError(f"{label} is not a regular file")
    return resolved


def _read_json_input(path: Path, label: str) -> tuple[dict[str, Any], Path]:
    resolved = _resolved_input(path, label)
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReadinessSummaryVerificationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ReadinessSummaryVerificationError(f"{label} root must be object")
    return value, resolved


def verify(summary: dict[str, Any], contract: dict[str, Any], run_verification: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise ReadinessSummaryVerificationError("production readiness contract identity mismatch")
    if run_verification.get("schema") != 1 or run_verification.get("kind") != "psmatrix.production-readiness-run-api-verification" or run_verification.get("version") != "2.0.0" or run_verification.get("status") != "PASS" or run_verification.get("readiness_pass_observed") is not True:
        raise ReadinessSummaryVerificationError("successful readiness run API verification is required")
    if summary.get("schema") != 1 or summary.get("kind") != "psmatrix.production-readiness-summary" or summary.get("version") != "2.0.0" or summary.get("status") != "PASS":
        raise ReadinessSummaryVerificationError("readiness summary identity/status mismatch")
    if summary.get("producer_source_anchor") != contract.get("producer_source_anchor") or summary.get("final_release_commit") != contract.get("final_release_commit"):
        raise ReadinessSummaryVerificationError("readiness summary frozen source/release identity mismatch")
    if summary.get("producer_source_coverage") != 11 or summary.get("environment_count") != 12 or summary.get("environment_passed") != 12 or summary.get("environment_failed") != 0 or summary.get("failed_environments") != [] or summary.get("environment_readiness") is not True:
        raise ReadinessSummaryVerificationError("readiness summary is not exact 12/12 PASS")
    rows = summary.get("environments")
    contract_rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12 or not isinstance(contract_rows, list) or len(contract_rows) != 12:
        raise ReadinessSummaryVerificationError("readiness environment cardinality mismatch")
    expected = {row["name"]: len(row.get("required_secrets") or []) + len(row.get("required_vars") or []) for row in contract_rows if isinstance(row, dict) and isinstance(row.get("name"), str)}
    if len(expected) != 12 or sum(expected.values()) != 41:
        raise ReadinessSummaryVerificationError("readiness contract check closure mismatch")
    observed: set[str] = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ReadinessSummaryVerificationError("readiness environment row must be object")
        name = row.get("environment")
        if name not in expected or name in observed or row.get("status") != "PASS" or row.get("required_checks") != expected[name] or row.get("missing") != [] or row.get("missing_paths") != []:
            raise ReadinessSummaryVerificationError(f"readiness environment row mismatch: {name}")
        observed.add(name)
        total += row["required_checks"]
    if observed != set(expected) or total != 41:
        raise ReadinessSummaryVerificationError("readiness summary does not close exact 41 checks")
    for field in ("secret_values_observed", "secret_hashes_observed", "secret_lengths_observed", "production_evidence_runs_complete", "production_evaluator_ready", "final_ga_evaluator_invoked", "ga_eligible"):
        if summary.get(field) is not False:
            raise ReadinessSummaryVerificationError(f"readiness summary crossed forbidden boundary: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_verification.get("run_id"),
        "exact_head": run_verification.get("exact_head"),
        "environment_count": 12,
        "verified_environment_count": 12,
        "required_check_count": 41,
        "verified_check_count": 41,
        "summary_content_verified": True,
        "production_readiness_verified": True,
        "production_evidence_runs_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def _write_readiness_summary_verification_receipt(
    path: Path,
    value: dict[str, Any],
) -> Path:
    _reject_symlink_components(path, "readiness summary verification output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise ReadinessSummaryVerificationError(
            "readiness summary verification output must not already exist"
        )
    parent = absolute.parent
    _reject_symlink_components(parent, "readiness summary verification output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise ReadinessSummaryVerificationError(
            "readiness summary verification output parent must already exist"
        )
    candidate = resolved_parent / absolute.name
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise ReadinessSummaryVerificationError(
            "readiness summary verification output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise ReadinessSummaryVerificationError(
            f"readiness summary verification output could not be created: {exc}"
        ) from exc

    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    handle = None
    success = False
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise ReadinessSummaryVerificationError(
                "readiness summary verification output path does not name the exclusively created file"
            )
        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise ReadinessSummaryVerificationError(
                "readiness summary verification output read-back verification failed"
            )
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise ReadinessSummaryVerificationError(
                "readiness summary verification output path identity changed during write"
            )
        success = True
        return candidate
    finally:
        if handle is not None:
            handle.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify downloaded Production GA readiness summary content against the frozen 12-environment/41-check contract")
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--run-verification", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary, summary_path = _read_json_input(
            args.summary,
            "readiness summary file",
        )
        contract, _ = _read_json_input(
            args.contract,
            "production readiness contract",
        )
        run_verification, _ = _read_json_input(
            args.run_verification,
            "readiness run verification",
        )
        value = verify(summary, contract, run_verification)
        value["summary_file_sha256"] = _file_sha256(summary_path)
        value["summary_file_size"] = summary_path.stat().st_size
        _write_readiness_summary_verification_receipt(args.output, value)
        print("production_readiness_summary_verification=PASS environments=12/12 checks=41/41")
        print(f"summary_file_sha256={value['summary_file_sha256']}")
        print(f"summary_file_size={value['summary_file_size']}")
        print("production_readiness_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ReadinessSummaryVerificationError, TypeError, ValueError, KeyError) as exc:
        print(f"production readiness summary verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
