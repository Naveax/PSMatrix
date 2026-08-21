from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_VERIFIER = ROOT / "scripts" / "ga" / "verify_public_auth_cross_gate_bundles.py"


class PublicAuthContentBindingError(RuntimeError):
    pass


def _safe_directory(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise PublicAuthContentBindingError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise PublicAuthContentBindingError(f"{label} is missing or unsafe")
    return resolved


def _safe_file(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise PublicAuthContentBindingError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise PublicAuthContentBindingError(f"{label} is missing or unsafe")
    return resolved


def _sha256(path: Path) -> str:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise PublicAuthContentBindingError("hash input is missing or unsafe")
    digest = hashlib.sha256()
    with candidate.resolve().open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_state(root: Path) -> dict[str, Any]:
    root = _safe_directory(root, "materialized public-auth root")
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise PublicAuthContentBindingError(f"symlink appeared in public-auth evidence tree: {path}")
        if path.is_file():
            files.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size, "sha256": _sha256(path)})
    if not files:
        raise PublicAuthContentBindingError("public-auth evidence tree has no files")
    digest = hashlib.sha256()
    for item in files:
        digest.update(f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8"))
    return {"file_count": len(files), "files": files, "tree_sha256": digest.hexdigest()}


def validate_materialization(value: dict[str, Any], gate: str, state: dict[str, Any]) -> None:
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.final-ga-evidence-artifact-materialization" or value.get("version") != "2.0.0" or value.get("status") != "PASS":
        raise PublicAuthContentBindingError(f"{gate}: materialization receipt identity mismatch")
    if value.get("gate") != gate or value.get("content_semantics_verified") is not False or value.get("ga_eligible") is not False:
        raise PublicAuthContentBindingError(f"{gate}: materialization receipt boundary mismatch")
    if type(value.get("run_id")) is not int or value["run_id"] <= 0 or type(value.get("artifact_id")) is not int or value["artifact_id"] <= 0:
        raise PublicAuthContentBindingError(f"{gate}: invalid run/artifact ID")
    if value.get("file_count") != state["file_count"] or value.get("tree_sha256") != state["tree_sha256"] or value.get("files") != state["files"]:
        raise PublicAuthContentBindingError(f"{gate}: materialized tree differs from API artifact receipt")


def run_semantic(oauth_root: Path, mtls_root: Path, extra_args: list[str]) -> dict[str, Any]:
    for value in extra_args:
        if value in {"--oauth-root", "--mtls-root", "--output"}:
            raise PublicAuthContentBindingError(f"reserved verifier argument: {value}")
    verifier_candidate = EXPECTED_VERIFIER
    if verifier_candidate.is_symlink():
        raise PublicAuthContentBindingError("repository-owned public-auth verifier is unavailable")
    script = verifier_candidate.resolve()
    ga_root = (ROOT / "scripts" / "ga").resolve()
    try:
        script.relative_to(ga_root)
    except ValueError as exc:
        raise PublicAuthContentBindingError("public-auth verifier resolved outside repository GA scripts") from exc
    if not script.is_file():
        raise PublicAuthContentBindingError("repository-owned public-auth verifier is unavailable")
    oauth_root = _safe_directory(oauth_root, "OAuth evidence root")
    mtls_root = _safe_directory(mtls_root, "mTLS evidence root")
    with tempfile.TemporaryDirectory(prefix="psmatrix-public-auth-semantic-") as temporary:
        output = Path(temporary) / "semantic-receipt.json"
        command = [sys.executable, str(script), "--oauth-root", str(oauth_root), "--mtls-root", str(mtls_root), *extra_args, "--output", str(output)]
        completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
        if completed.returncode != 0:
            raise PublicAuthContentBindingError(f"public-auth semantic verifier failed: {completed.stdout.strip()}")
        if not output.is_file() or output.is_symlink():
            raise PublicAuthContentBindingError("public-auth semantic verifier did not emit a safe receipt")
        semantic = json.loads(output.read_text(encoding="utf-8"))
        if semantic.get("schema") != 1 or semantic.get("kind") != "psmatrix.public-auth-cross-gate-bundle-verification" or semantic.get("version") != "2.0.0" or semantic.get("status") != "PASS" or semantic.get("ga_eligible") is not False:
            raise PublicAuthContentBindingError("public-auth semantic receipt identity/boundary mismatch")
        semantic["_receipt_sha256"] = _sha256(output)
        return semantic


def bind(oauth_materialization: dict[str, Any], mtls_materialization: dict[str, Any], oauth_before: dict[str, Any], oauth_after: dict[str, Any], mtls_before: dict[str, Any], mtls_after: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]:
    validate_materialization(oauth_materialization, "public-oauth", oauth_before)
    validate_materialization(mtls_materialization, "public-mtls", mtls_before)
    if oauth_after != oauth_before or mtls_after != mtls_before:
        raise PublicAuthContentBindingError("public-auth semantic verification mutated an evidence tree")
    if oauth_materialization.get("execution_head") != mtls_materialization.get("execution_head"):
        raise PublicAuthContentBindingError("OAuth/mTLS materializations do not share one execution head")
    if oauth_materialization["run_id"] == mtls_materialization["run_id"] or oauth_materialization["artifact_id"] == mtls_materialization["artifact_id"]:
        raise PublicAuthContentBindingError("OAuth/mTLS require distinct run and artifact identities")
    if semantic.get("schema") != 1 or semantic.get("kind") != "psmatrix.public-auth-cross-gate-bundle-verification" or semantic.get("version") != "2.0.0" or semantic.get("status") != "PASS" or semantic.get("ga_eligible") is not False:
        raise PublicAuthContentBindingError("public-auth semantic receipt identity/boundary mismatch")
    receipt_sha = semantic.get("_receipt_sha256")
    if not isinstance(receipt_sha, str) or len(receipt_sha) != 64:
        raise PublicAuthContentBindingError("public-auth semantic receipt SHA-256 is missing")
    for field in ("same_live_report_sha256", "different_public_endpoints", "same_deployment_authority", "same_release_manifest_sha256", "same_release_wheel_sha256", "oauth_proof_verified", "mtls_proof_verified"):
        if semantic.get(field) is not True:
            raise PublicAuthContentBindingError(f"public-auth semantic closure field failed: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.public-auth-cross-gate-content-binding",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": oauth_materialization.get("execution_head"),
        "covered_gates": ["public-oauth", "public-mtls"],
        "run_ids": {"public-oauth": oauth_materialization["run_id"], "public-mtls": mtls_materialization["run_id"]},
        "artifact_ids": {"public-oauth": oauth_materialization["artifact_id"], "public-mtls": mtls_materialization["artifact_id"]},
        "tree_sha256": {"public-oauth": oauth_before["tree_sha256"], "public-mtls": mtls_before["tree_sha256"]},
        "semantic_receipt_sha256": receipt_sha,
        "api_artifact_origin_verified": True,
        "both_materialized_trees_verified": True,
        "semantic_verifier_repository_owned": True,
        "semantic_verification_mutated_tree": False,
        "content_semantics_verified": True,
        "cross_gate_semantics_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind exact OAuth/mTLS API artifact provenance to the shared public-auth cross-gate semantic verifier")
    parser.add_argument("--oauth-materialization-receipt", type=Path, required=True)
    parser.add_argument("--mtls-materialization-receipt", type=Path, required=True)
    parser.add_argument("--oauth-root", type=Path, required=True)
    parser.add_argument("--mtls-root", type=Path, required=True)
    parser.add_argument("--verifier-arg", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        oauth_receipt = _safe_file(args.oauth_materialization_receipt, "OAuth materialization receipt")
        mtls_receipt = _safe_file(args.mtls_materialization_receipt, "mTLS materialization receipt")
        oauth_materialization = json.loads(oauth_receipt.read_text(encoding="utf-8"))
        mtls_materialization = json.loads(mtls_receipt.read_text(encoding="utf-8"))
        oauth_before = tree_state(args.oauth_root)
        mtls_before = tree_state(args.mtls_root)
        validate_materialization(oauth_materialization, "public-oauth", oauth_before)
        validate_materialization(mtls_materialization, "public-mtls", mtls_before)
        semantic = run_semantic(args.oauth_root, args.mtls_root, list(args.verifier_arg))
        value = bind(oauth_materialization, mtls_materialization, oauth_before, tree_state(args.oauth_root), mtls_before, tree_state(args.mtls_root), semantic)
        output = Path(args.output).expanduser()
        if output.is_symlink():
            raise PublicAuthContentBindingError("public-auth content-binding output is unsafe")
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("public_auth_content_binding=PASS gates=2/2")
        print("cross_gate_semantics_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, PublicAuthContentBindingError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"public-auth content binding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
