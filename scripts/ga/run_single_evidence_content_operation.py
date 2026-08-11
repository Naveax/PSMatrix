from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATERIALIZER = ROOT / "scripts" / "ga" / "materialize_verified_evidence_artifact.py"
BINDER = ROOT / "scripts" / "ga" / "bind_verified_evidence_content.py"
ALLOWED_FLAGS = {
    "validation-summary": (),
    "signed-release": ("--active-lock", "--run-verification"),
    "authoritative-windows": ("--lab-public-key",),
    "complete-runtime-matrix": (),
    "external-otlp": ("--release-public-key",),
    "key-rotation": ("--protected-release-public-key",),
    "disaster-recovery": (),
    "security-review": ("--release-public-key",),
    "vulnerability-scan": ("--release-public-key", "--security-review-public-key"),
}


class SingleEvidenceContentOperationError(RuntimeError):
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
        raise SingleEvidenceContentOperationError("evidence content workspace must stay outside repository")
    if resolved.exists() and any(resolved.iterdir()):
        raise SingleEvidenceContentOperationError("evidence content workspace must be absent or empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def validate_verifier_args(gate: str, args: list[str]) -> list[str]:
    expected = ALLOWED_FLAGS.get(gate)
    if expected is None:
        raise SingleEvidenceContentOperationError(f"unsupported single-artifact evidence gate: {gate}")
    if len(args) != len(expected) * 2:
        raise SingleEvidenceContentOperationError(f"{gate} requires exact verifier flags: {','.join(expected) or '<none>'}")
    observed: dict[str, str] = {}
    for index in range(0, len(args), 2):
        flag = args[index]
        raw = args[index + 1]
        if flag not in expected or flag in observed:
            raise SingleEvidenceContentOperationError(f"unexpected or duplicate verifier flag for {gate}: {flag}")
        if not raw or "\x00" in raw:
            raise SingleEvidenceContentOperationError(f"empty verifier path for {gate}/{flag}")
        path = Path(raw).expanduser().resolve()
        if not path.is_file() or path.is_symlink():
            raise SingleEvidenceContentOperationError(f"verifier support file is missing or unsafe: {gate}/{flag}")
        observed[flag] = str(path)
    if set(observed) != set(expected):
        raise SingleEvidenceContentOperationError(f"verifier flag set mismatch for {gate}")
    normalized: list[str] = []
    for flag in expected:
        normalized.extend([flag, observed[flag]])
    return normalized


def _run(command: list[str], label: str) -> None:
    completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
    if completed.returncode != 0:
        raise SingleEvidenceContentOperationError(f"{label} failed: {completed.stdout.strip()}")


def run_operation(api_verification: Path, gate: str, workspace: Path, verifier_args: list[str], repository: str, gh: str) -> dict[str, Any]:
    if gate not in ALLOWED_FLAGS:
        raise SingleEvidenceContentOperationError(f"unsupported single-artifact evidence gate: {gate}")
    if not api_verification.resolve().is_file() or api_verification.resolve().is_symlink():
        raise SingleEvidenceContentOperationError("evidence API verification is missing or unsafe")
    normalized_args = validate_verifier_args(gate, verifier_args)
    root = _external_workspace(workspace)
    materialized = root / "artifact"
    materialization_receipt = root / "materialization.json"
    binding_receipt = root / "content-binding.json"

    _run([
        sys.executable,
        str(MATERIALIZER),
        "--api-verification", str(api_verification.resolve()),
        "--gate", gate,
        "--destination", str(materialized),
        "--receipt", str(materialization_receipt),
        "--repository", repository,
        "--gh", gh,
    ], "artifact materialization")

    binder_command = [
        sys.executable,
        str(BINDER),
        "--materialization-receipt", str(materialization_receipt),
        "--gate", gate,
        "--bundle-root", str(materialized),
    ]
    for index in range(0, len(normalized_args), 2):
        binder_command.extend(["--verifier-arg", normalized_args[index], "--verifier-arg", normalized_args[index + 1]])
    binder_command.extend(["--output", str(binding_receipt)])
    _run(binder_command, "content semantic binding")

    binding = json.loads(binding_receipt.read_text(encoding="utf-8"))
    if binding.get("schema") != 1 or binding.get("kind") != "psmatrix.final-ga-evidence-content-binding" or binding.get("version") != "2.0.0" or binding.get("status") != "PASS" or binding.get("gate") != gate or binding.get("content_semantics_verified") is not True or binding.get("ga_eligible") is not False:
        raise SingleEvidenceContentOperationError("content binding receipt identity/boundary mismatch")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-single-evidence-content-operation",
        "version": "2.0.0",
        "status": "PASS",
        "gate": gate,
        "execution_head": binding.get("execution_head"),
        "run_id": binding.get("run_id"),
        "artifact_id": binding.get("artifact_id"),
        "binding_receipt": str(binding_receipt),
        "binding_receipt_sha256": _sha256(binding_receipt),
        "api_artifact_origin_verified": True,
        "materialized_tree_verified": True,
        "content_semantics_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize and semantically bind one exact API-verified final GA evidence artifact")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--verifier-arg", action="append", default=[])
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = run_operation(args.api_verification, args.gate, args.workspace, list(args.verifier_arg), args.repository, args.gh)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"single_evidence_content_operation=PASS gate={value['gate']} run={value['run_id']} artifact_id={value['artifact_id']}")
        print("content_semantics_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, SingleEvidenceContentOperationError, TypeError, ValueError, KeyError) as exc:
        print(f"single evidence content operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
