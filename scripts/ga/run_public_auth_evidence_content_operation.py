from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATERIALIZER = ROOT / "scripts" / "ga" / "materialize_verified_evidence_artifact.py"
BINDER = ROOT / "scripts" / "ga" / "bind_public_auth_evidence_content.py"


class PublicAuthEvidenceContentOperationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _external_workspace(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise PublicAuthEvidenceContentOperationError("public-auth evidence workspace must stay outside repository")
    if resolved.exists() and any(resolved.iterdir()):
        raise PublicAuthEvidenceContentOperationError("public-auth evidence workspace must be absent or empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _run(command: list[str], label: str) -> None:
    completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
    if completed.returncode != 0:
        raise PublicAuthEvidenceContentOperationError(f"{label} failed: {completed.stdout.strip()}")


def validate_binding(binding: dict[str, Any]) -> None:
    if binding.get("schema") != 1 or binding.get("kind") != "psmatrix.public-auth-cross-gate-content-binding" or binding.get("version") != "2.0.0" or binding.get("status") != "PASS":
        raise PublicAuthEvidenceContentOperationError("public-auth content binding identity/status mismatch")
    if binding.get("covered_gates") != ["public-oauth", "public-mtls"] or binding.get("cross_gate_semantics_verified") is not True or binding.get("content_semantics_verified") is not True:
        raise PublicAuthEvidenceContentOperationError("public-auth cross-gate content closure mismatch")
    run_ids = binding.get("run_ids")
    artifact_ids = binding.get("artifact_ids")
    if not isinstance(run_ids, dict) or not isinstance(artifact_ids, dict) or set(run_ids) != {"public-oauth", "public-mtls"} or set(artifact_ids) != {"public-oauth", "public-mtls"}:
        raise PublicAuthEvidenceContentOperationError("public-auth provenance maps mismatch")
    if len(set(run_ids.values())) != 2 or len(set(artifact_ids.values())) != 2:
        raise PublicAuthEvidenceContentOperationError("OAuth/mTLS require distinct run and artifact identities")
    if binding.get("final_ga_evaluator_invoked") is not False or binding.get("ga_eligible") is not False:
        raise PublicAuthEvidenceContentOperationError("public-auth binding crossed evaluator/GA boundary")


def run_operation(api_verification: Path, workspace: Path, repository: str, gh: str) -> dict[str, Any]:
    api_path = api_verification.expanduser().resolve()
    if not api_path.is_file() or api_path.is_symlink():
        raise PublicAuthEvidenceContentOperationError("evidence API verification is missing or unsafe")
    root = _external_workspace(workspace)
    paths: dict[str, dict[str, Path]] = {}
    for gate in ("public-oauth", "public-mtls"):
        gate_root = root / gate
        artifact_root = gate_root / "artifact"
        materialization = gate_root / "materialization.json"
        gate_root.mkdir(parents=True, exist_ok=True)
        _run([
            sys.executable,
            str(MATERIALIZER),
            "--api-verification", str(api_path),
            "--gate", gate,
            "--destination", str(artifact_root),
            "--receipt", str(materialization),
            "--repository", repository,
            "--gh", gh,
        ], f"{gate} artifact materialization")
        paths[gate] = {"root": artifact_root, "receipt": materialization}

    binding_receipt = root / "public-auth-content-binding.json"
    _run([
        sys.executable,
        str(BINDER),
        "--oauth-materialization-receipt", str(paths["public-oauth"]["receipt"]),
        "--mtls-materialization-receipt", str(paths["public-mtls"]["receipt"]),
        "--oauth-root", str(paths["public-oauth"]["root"]),
        "--mtls-root", str(paths["public-mtls"]["root"]),
        "--output", str(binding_receipt),
    ], "public-auth cross-gate content binding")

    binding = json.loads(binding_receipt.read_text(encoding="utf-8"))
    validate_binding(binding)
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-public-auth-evidence-content-operation",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": binding.get("execution_head"),
        "covered_gates": ["public-oauth", "public-mtls"],
        "run_ids": binding["run_ids"],
        "artifact_ids": binding["artifact_ids"],
        "binding_receipt": str(binding_receipt),
        "binding_receipt_sha256": _sha256(binding_receipt),
        "api_artifact_origins_verified": True,
        "both_materialized_trees_verified": True,
        "content_semantics_verified": True,
        "cross_gate_semantics_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize and semantically bind exact OAuth/mTLS final GA evidence artifacts as one cross-gate operation")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = run_operation(args.api_verification, args.workspace, args.repository, args.gh)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("public_auth_evidence_content_operation=PASS gates=2/2")
        print("cross_gate_semantics_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, PublicAuthEvidenceContentOperationError, TypeError, ValueError, KeyError) as exc:
        print(f"public-auth evidence content operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
