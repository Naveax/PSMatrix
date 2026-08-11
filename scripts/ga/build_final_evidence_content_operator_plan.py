from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_GATES = (
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
)
SUPPORT_KEYS = (
    "active_lock",
    "release_signing_run_verification",
    "windows_lab_public_key",
    "release_public_key",
    "security_review_public_key",
)
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)


class EvidenceContentOperatorPlanError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_file(base: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise EvidenceContentOperatorPlanError(f"support file path is invalid: {label}")
    supplied = Path(raw).expanduser()
    path = (supplied if supplied.is_absolute() else base / supplied).resolve()
    if not path.is_file() or path.is_symlink():
        raise EvidenceContentOperatorPlanError(f"support file is missing or unsafe: {label}")
    return path


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceContentOperatorPlanError(f"support JSON is invalid: {label}") from exc
    if not isinstance(value, dict):
        raise EvidenceContentOperatorPlanError(f"support JSON root must be object: {label}")
    return value


def _api_rows(api: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    if api.get("schema") != 1 or api.get("kind") != "psmatrix.final-ga-evidence-api-verification" or api.get("version") != "2.0.0" or api.get("status") != "PASS" or api.get("verified_gate_count") != 11:
        raise EvidenceContentOperatorPlanError("exact 11/11 evidence API verification is required")
    head = api.get("execution_head")
    if not isinstance(head, str) or len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise EvidenceContentOperatorPlanError("evidence execution head is invalid")
    rows = api.get("gates")
    if not isinstance(rows, list) or len(rows) != 11:
        raise EvidenceContentOperatorPlanError("evidence API gate cardinality mismatch")
    mapped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceContentOperatorPlanError("evidence API gate row must be object")
        gate = row.get("gate")
        if gate not in REQUIRED_GATES or gate in mapped or row.get("verified") is not True:
            raise EvidenceContentOperatorPlanError(f"invalid or duplicate evidence gate row: {gate}")
        if type(row.get("run_id")) is not int or row["run_id"] <= 0 or type(row.get("artifact_id")) is not int or row["artifact_id"] <= 0 or not str(row.get("artifact") or ""):
            raise EvidenceContentOperatorPlanError(f"incomplete evidence provenance row: {gate}")
        mapped[str(gate)] = row
    if tuple(mapped.keys()) != REQUIRED_GATES:
        raise EvidenceContentOperatorPlanError("evidence API rows must preserve exact canonical gate order")
    if len({row["run_id"] for row in mapped.values()}) != 11 or len({row["artifact_id"] for row in mapped.values()}) != 11:
        raise EvidenceContentOperatorPlanError("evidence run/artifact identities must be distinct")
    return head, mapped


def build(api: dict[str, Any], support_manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    head, rows = _api_rows(api)
    if support_manifest.get("schema") != 1 or support_manifest.get("kind") != "psmatrix.final-ga-evidence-content-support-files" or support_manifest.get("version") != "2.0.0":
        raise EvidenceContentOperatorPlanError("support manifest identity mismatch")
    files = support_manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(SUPPORT_KEYS):
        raise EvidenceContentOperatorPlanError("support manifest must declare exact five support files")
    base = manifest_path.resolve().parent
    resolved = {name: _safe_file(base, files[name], name) for name in SUPPORT_KEYS}

    lock = _json(resolved["active_lock"], "active_lock")
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-final-release-staging-lock" or lock.get("version") != "2.0.0" or lock.get("promotion_state") != "READY_FOR_EXACT_REPOSITORY_COMMIT":
        raise EvidenceContentOperatorPlanError("active lock identity/state mismatch")
    signing = _json(resolved["release_signing_run_verification"], "release_signing_run_verification")
    if signing.get("schema") != 1 or signing.get("kind") != "psmatrix.final-release-signing-run-api-verification" or signing.get("version") != "2.0.0" or signing.get("status") != "PASS" or signing.get("signed_release_run_verified") is not True or signing.get("execution_head") != head:
        raise EvidenceContentOperatorPlanError("release signing run verification does not PASS on the evidence execution head")
    if signing.get("run_id") != rows["signed-release"]["run_id"]:
        raise EvidenceContentOperatorPlanError("release signing run verification differs from signed-release gate provenance")

    public_keys = ("windows_lab_public_key", "release_public_key", "security_review_public_key")
    for name in public_keys:
        data = resolved[name].read_bytes()
        if not data or any(marker in data for marker in PRIVATE_MARKERS):
            raise EvidenceContentOperatorPlanError(f"public support file is empty or contains private-key material: {name}")
    if len({_sha256(resolved[name]) for name in public_keys}) != 3:
        raise EvidenceContentOperatorPlanError("Windows Lab, release, and security-review public authorities must be distinct")

    support = {
        name: {"path": str(path), "sha256": _sha256(path), "size": path.stat().st_size}
        for name, path in resolved.items()
    }
    extra: dict[str, list[str]] = {
        "validation-summary": [],
        "signed-release": ["--active-lock", str(resolved["active_lock"]), "--run-verification", str(resolved["release_signing_run_verification"])],
        "authoritative-windows": ["--lab-public-key", str(resolved["windows_lab_public_key"])],
        "complete-runtime-matrix": [],
        "external-otlp": ["--release-public-key", str(resolved["release_public_key"])],
        "key-rotation": ["--protected-release-public-key", str(resolved["release_public_key"])],
        "disaster-recovery": [],
        "security-review": ["--release-public-key", str(resolved["release_public_key"])],
        "vulnerability-scan": ["--release-public-key", str(resolved["release_public_key"]), "--security-review-public-key", str(resolved["security_review_public_key"])],
    }
    gates = []
    for gate in REQUIRED_GATES:
        row = rows[gate]
        gates.append({
            "gate": gate,
            "run_id": row["run_id"],
            "artifact": row["artifact"],
            "artifact_id": row["artifact_id"],
            "binding_mode": "public-auth-cross-gate" if gate in {"public-oauth", "public-mtls"} else "single-artifact",
            "verifier_args": [] if gate in {"public-oauth", "public-mtls"} else extra[gate],
        })
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-operator-plan",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": head,
        "required_gate_count": 11,
        "single_artifact_gate_count": 9,
        "public_auth_gate_count": 2,
        "support_file_count": 5,
        "support_files": support,
        "gates": gates,
        "ready_for_artifact_materialization": True,
        "content_semantics_verified": False,
        "content_closure_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the exact fail-closed plan for materializing and verifying all 11 final GA evidence artifacts")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--support-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api = json.loads(args.api_verification.read_text(encoding="utf-8"))
        support = json.loads(args.support_manifest.read_text(encoding="utf-8"))
        value = build(api, support, args.support_manifest)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_content_operator_plan=PASS gates=11/11 support_files=5")
        print("ready_for_artifact_materialization=true")
        print("content_closure_complete=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceContentOperatorPlanError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evidence content operator plan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
