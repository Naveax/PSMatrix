from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

GATE_VERIFIERS = {
    "validation-summary": ("verify_final_validation_summary_bundle.py", "psmatrix.final-validation-summary-bundle-verification"),
    "signed-release": ("verify_protected_final_release_bundle.py", "psmatrix.protected-final-release-bundle-verification"),
    "authoritative-windows": ("verify_final_windows_rebind_bundle.py", "psmatrix.final-windows-rebind-bundle-verification"),
    "complete-runtime-matrix": ("verify_full_runtime_matrix_bundle.py", "psmatrix.full-runtime-matrix-bundle-verification"),
    "external-otlp": ("verify_external_otlp_bundle.py", "psmatrix.external-otlp-bundle-verification"),
    "key-rotation": ("verify_key_rotation_bundle.py", "psmatrix.key-rotation-bundle-verification"),
    "disaster-recovery": ("verify_disaster_recovery_bundle.py", "psmatrix.disaster-recovery-bundle-verification"),
    "security-review": ("verify_security_review_bundle.py", "psmatrix.security-review-bundle-verification"),
    "vulnerability-scan": ("verify_vulnerability_scan_bundle.py", "psmatrix.vulnerability-scan-bundle-verification"),
}
RESERVED_ARGS = {"--bundle-root", "--output"}


class EvidenceContentBindingError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_state(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise EvidenceContentBindingError("materialized evidence root is missing")
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise EvidenceContentBindingError(f"symlink appeared in materialized evidence tree: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
    if not files:
        raise EvidenceContentBindingError("materialized evidence tree has no files")
    digest = hashlib.sha256()
    for item in files:
        digest.update(f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8"))
    return {"file_count": len(files), "files": files, "tree_sha256": digest.hexdigest()}


def validate_materialization(materialization: dict[str, Any], gate: str, state: dict[str, Any]) -> None:
    if materialization.get("schema") != 1 or materialization.get("kind") != "psmatrix.final-ga-evidence-artifact-materialization" or materialization.get("version") != "2.0.0" or materialization.get("status") != "PASS":
        raise EvidenceContentBindingError("artifact materialization receipt identity mismatch")
    if materialization.get("gate") != gate or materialization.get("content_semantics_verified") is not False or materialization.get("ga_eligible") is not False:
        raise EvidenceContentBindingError("artifact materialization gate/boundary mismatch")
    if type(materialization.get("run_id")) is not int or materialization["run_id"] <= 0 or type(materialization.get("artifact_id")) is not int or materialization["artifact_id"] <= 0:
        raise EvidenceContentBindingError("artifact materialization provenance identifiers are invalid")
    if materialization.get("file_count") != state["file_count"] or materialization.get("tree_sha256") != state["tree_sha256"] or materialization.get("files") != state["files"]:
        raise EvidenceContentBindingError("materialized evidence tree differs from API-download receipt")


def validate_semantic_receipt(gate: str, semantic: dict[str, Any]) -> None:
    expected = GATE_VERIFIERS.get(gate)
    if expected is None:
        raise EvidenceContentBindingError(f"gate is not supported by the single-artifact content binder: {gate}")
    _, expected_kind = expected
    if semantic.get("schema") != 1 or semantic.get("kind") != expected_kind or semantic.get("version") != "2.0.0" or semantic.get("status") != "PASS":
        raise EvidenceContentBindingError(f"semantic receipt identity/status mismatch for {gate}")
    if semantic.get("ga_eligible") is not False:
        raise EvidenceContentBindingError("individual evidence semantic receipt may not claim GA eligibility")


def run_verifier(gate: str, bundle_root: Path, extra_args: list[str]) -> dict[str, Any]:
    if gate not in GATE_VERIFIERS:
        raise EvidenceContentBindingError(f"unsupported single-artifact gate: {gate}")
    for value in extra_args:
        if value in RESERVED_ARGS:
            raise EvidenceContentBindingError(f"verifier extra argument is reserved: {value}")
    script_name, _ = GATE_VERIFIERS[gate]
    script = (ROOT / "scripts" / "ga" / script_name).resolve()
    ga_root = (ROOT / "scripts" / "ga").resolve()
    try:
        script.relative_to(ga_root)
    except ValueError as exc:
        raise EvidenceContentBindingError("gate verifier resolved outside repository GA scripts") from exc
    if not script.is_file() or script.is_symlink():
        raise EvidenceContentBindingError(f"repository-owned gate verifier is unavailable: {script_name}")
    with tempfile.TemporaryDirectory(prefix=f"psmatrix-{gate}-semantic-") as temporary:
        output = Path(temporary) / "semantic-receipt.json"
        command = [sys.executable, str(script), "--bundle-root", str(bundle_root.resolve()), *extra_args, "--output", str(output)]
        completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
        if completed.returncode != 0:
            raise EvidenceContentBindingError(f"{gate} semantic verifier failed: {completed.stdout.strip()}")
        if not output.is_file():
            raise EvidenceContentBindingError(f"{gate} semantic verifier did not produce its receipt")
        try:
            semantic = json.loads(output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise EvidenceContentBindingError(f"{gate} semantic verifier produced invalid JSON") from exc
        validate_semantic_receipt(gate, semantic)
        semantic["_receipt_sha256"] = _sha256(output)
        return semantic


def bind(materialization: dict[str, Any], gate: str, before: dict[str, Any], after: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]:
    validate_materialization(materialization, gate, before)
    if after != before:
        raise EvidenceContentBindingError("semantic verification mutated the materialized evidence tree")
    validate_semantic_receipt(gate, semantic)
    receipt_sha = semantic.get("_receipt_sha256")
    if not isinstance(receipt_sha, str) or len(receipt_sha) != 64:
        raise EvidenceContentBindingError("semantic receipt SHA-256 is missing")
    clean_semantic = {key: value for key, value in semantic.items() if key != "_receipt_sha256"}
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-binding",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": materialization.get("execution_head"),
        "gate": gate,
        "run_id": materialization["run_id"],
        "artifact": materialization.get("artifact"),
        "artifact_id": materialization["artifact_id"],
        "artifact_archive_sha256": materialization.get("artifact_archive_sha256"),
        "materialized_tree_sha256": before["tree_sha256"],
        "materialized_file_count": before["file_count"],
        "semantic_receipt_kind": clean_semantic["kind"],
        "semantic_receipt_sha256": receipt_sha,
        "api_artifact_origin_verified": True,
        "materialized_tree_verified": True,
        "semantic_verifier_repository_owned": True,
        "semantic_verification_mutated_tree": False,
        "content_semantics_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a repository-owned gate verifier on an API-materialized evidence tree and bind provenance to content semantics")
    parser.add_argument("--materialization-receipt", type=Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--verifier-arg", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        materialization = json.loads(args.materialization_receipt.read_text(encoding="utf-8"))
        before = tree_state(args.bundle_root)
        validate_materialization(materialization, args.gate, before)
        semantic = run_verifier(args.gate, args.bundle_root, list(args.verifier_arg))
        after = tree_state(args.bundle_root)
        value = bind(materialization, args.gate, before, after, semantic)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"evidence_content_binding=PASS gate={args.gate} run={value['run_id']} artifact_id={value['artifact_id']}")
        print("content_semantics_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceContentBindingError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"evidence content binding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
