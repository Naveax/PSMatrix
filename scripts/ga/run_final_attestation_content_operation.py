from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATERIALIZER_PATH = ROOT / "scripts" / "ga" / "materialize_verified_evidence_artifact.py"
VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_final_ga_attestation_bundle.py"
ARTIFACT = "psmatrix-2.0.0-final-ga-attestation"


class FinalAttestationContentOperationError(RuntimeError):
    pass


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FinalAttestationContentOperationError(f"unable to load repository-owned module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_state(root: Path) -> tuple[str, list[dict[str, Any]]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise FinalAttestationContentOperationError(f"symlink found in materialized final attestation tree: {path.name}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
    if not files:
        raise FinalAttestationContentOperationError("materialized final attestation tree is empty")
    digest = hashlib.sha256()
    for row in files:
        digest.update(f"{row['path']}\0{row['size']}\0{row['sha256']}\n".encode("utf-8"))
    return digest.hexdigest(), files


def validate_run_verification(value: dict[str, Any]) -> tuple[int, str]:
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.final-ga-evaluator-run-api-verification" or value.get("version") != "2.0.0" or value.get("status") != "PASS":
        raise FinalAttestationContentOperationError("final evaluator run verification identity/status mismatch")
    if value.get("final_ga_evaluator_run_verified") is not True or value.get("ga_root_signing_run_completed") is not True or value.get("content_closure_required") is not True:
        raise FinalAttestationContentOperationError("evaluator/root run verification is incomplete")
    if value.get("api_verified_gate_count_before_dispatch") != 11 or value.get("content_verified_gate_count_before_dispatch") != 11:
        raise FinalAttestationContentOperationError("evaluator run was not preceded by exact 11/11 API/content closure")
    if value.get("final_attestation_artifact") != ARTIFACT or value.get("final_attestation_artifact_nonexpired") is not True:
        raise FinalAttestationContentOperationError("final attestation artifact identity/expiry mismatch")
    artifact_id = value.get("final_attestation_artifact_id")
    head = value.get("execution_head")
    if type(artifact_id) is not int or artifact_id <= 0 or not isinstance(head, str) or len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise FinalAttestationContentOperationError("final attestation artifact ID or execution head is invalid")
    if value.get("final_attestation_content_verified") is not False or value.get("ga_eligible") is not False:
        raise FinalAttestationContentOperationError("run verification must remain pre-content-verification/GA")
    return artifact_id, head


def _external_workspace(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise FinalAttestationContentOperationError("final attestation workspace must stay outside repository")
    if resolved.exists() and any(resolved.iterdir()):
        raise FinalAttestationContentOperationError("final attestation workspace must be absent or empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def run_operation(run_verification: Path, workspace: Path, repository: str, gh: str) -> dict[str, Any]:
    receipt_path = run_verification.expanduser().resolve()
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise FinalAttestationContentOperationError("final evaluator run verification receipt is missing or unsafe")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    artifact_id, head = validate_run_verification(receipt)
    root = _external_workspace(workspace)
    materializer = _load(MATERIALIZER_PATH, "psmatrix_final_attestation_materializer")
    verifier = _load(VERIFIER_PATH, "psmatrix_final_attestation_verifier")
    archive_root = Path(tempfile.mkdtemp(prefix="psmatrix-final-attestation-"))
    archive = archive_root / f"artifact-{artifact_id}.zip"
    bundle_root = root / "bundle"
    verification_path = root / "final-attestation-verification.json"
    try:
        materializer.download(gh, repository, artifact_id, archive)
        archive_sha = materializer._sha256(archive)
        extracted = materializer.safe_extract(archive, bundle_root)
        before_tree, before_files = _tree_state(bundle_root)
        if before_tree != extracted.get("tree_sha256") or len(before_files) != extracted.get("file_count"):
            raise FinalAttestationContentOperationError("safe extraction tree receipt mismatch")
        verification = verifier.verify(bundle_root, head)
        if verification.get("schema") != 1 or verification.get("kind") != "psmatrix.final-ga-attestation-bundle-verification" or verification.get("version") != "2.0.0" or verification.get("status") != "PASS" or verification.get("final_ga_attestation_verified") is not True or verification.get("ga_eligible") is not True:
            raise FinalAttestationContentOperationError("independent final attestation verification did not prove GA eligibility")
        verification_path.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        after_tree, after_files = _tree_state(bundle_root)
        if after_tree != before_tree or after_files != before_files:
            raise FinalAttestationContentOperationError("final attestation semantic verifier mutated materialized artifact tree")
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-content-operation",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": head,
            "evaluator_run_id": receipt.get("run_id"),
            "artifact": ARTIFACT,
            "artifact_id": artifact_id,
            "artifact_archive_sha256": archive_sha,
            "materialized_file_count": len(before_files),
            "materialized_tree_sha256": before_tree,
            "verification_receipt": str(verification_path),
            "verification_receipt_sha256": _sha256(verification_path),
            "exact_api_artifact_id_used": True,
            "safe_extraction_verified": True,
            "semantic_verifier_repository_owned": True,
            "semantic_verification_mutated_tree": False,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
    finally:
        shutil.rmtree(archive_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Download the exact final evaluator artifact and independently verify final GA attestation content")
    parser.add_argument("--run-verification", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = run_operation(args.run_verification, args.workspace, args.repository, args.gh)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_ga_attestation_content_operation=PASS run={value['evaluator_run_id']} artifact_id={value['artifact_id']}")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, FinalAttestationContentOperationError, TypeError, ValueError, KeyError, Exception) as exc:
        print(f"final GA attestation content operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
