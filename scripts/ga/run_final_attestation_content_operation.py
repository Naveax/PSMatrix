from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
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
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise FinalAttestationContentOperationError(f"repository-owned module failed to load: {path.name}: {exc}") from exc
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
    if type(value.get("run_id")) is not int or value["run_id"] <= 0:
        raise FinalAttestationContentOperationError("final evaluator run ID is invalid")
    if value.get("final_attestation_content_verified") is not False or value.get("ga_eligible") is not False:
        raise FinalAttestationContentOperationError("run verification must remain pre-content-verification/GA")
    return artifact_id, head


def _absolute(path: Path) -> Path:
    raw = Path(path).expanduser()
    return raw if raw.is_absolute() else Path.cwd() / raw


def _reject_symlink_components(path: Path, *, label: str) -> Path:
    raw = _absolute(path)
    for component in [raw, *raw.parents]:
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FinalAttestationContentOperationError(f"unable to inspect {label}: {component}") from exc
        if stat.S_ISLNK(mode):
            raise FinalAttestationContentOperationError(f"{label} contains a symlink component: {component}")
    return raw


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    raw = _reject_symlink_components(path, label=label)
    try:
        resolved = raw.resolve(strict=True)
        item = resolved.lstat()
        if not stat.S_ISREG(item.st_mode):
            raise FinalAttestationContentOperationError(f"{label} must be a regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalAttestationContentOperationError(f"unable to read {label}: {raw}") from exc
    if not isinstance(value, dict):
        raise FinalAttestationContentOperationError(f"{label} root must be an object")
    return value


def _write_json_once(path: Path, payload: dict[str, Any], *, label: str) -> Path:
    raw = _reject_symlink_components(path, label=label)
    parent = raw.parent
    if not parent.exists() or not parent.is_dir():
        raise FinalAttestationContentOperationError(f"{label} parent must already exist")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / raw.name
    _reject_symlink_components(candidate, label=label)
    try:
        candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FinalAttestationContentOperationError(f"unable to inspect {label}: {candidate}") from exc
    else:
        raise FinalAttestationContentOperationError(f"{label} must not already exist")

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise FinalAttestationContentOperationError(f"{label} is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        current = candidate.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FinalAttestationContentOperationError(f"{label} changed type during write")
        if (current.st_dev, current.st_ino) != created_identity:
            raise FinalAttestationContentOperationError(f"{label} path changed identity during write")
        if candidate.read_text(encoding="utf-8") != text:
            raise FinalAttestationContentOperationError(f"{label} read-back mismatch")
        return candidate
    except Exception:
        if fd is not None:
            os.close(fd)
        if created_identity is not None:
            try:
                current = candidate.lstat()
            except FileNotFoundError:
                pass
            else:
                if (
                    not stat.S_ISLNK(current.st_mode)
                    and stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    candidate.unlink()
        raise


def _external_workspace(path: Path) -> Path:
    raw = _reject_symlink_components(path, label="final attestation workspace")
    parent = raw.parent
    if not parent.exists() or not parent.is_dir():
        raise FinalAttestationContentOperationError("final attestation workspace parent must already exist")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / raw.name
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise FinalAttestationContentOperationError("final attestation workspace must stay outside repository")
    _reject_symlink_components(candidate, label="final attestation workspace")
    if candidate.exists():
        item = candidate.lstat()
        if not stat.S_ISDIR(item.st_mode):
            raise FinalAttestationContentOperationError("final attestation workspace must be a real directory")
        if any(candidate.iterdir()):
            raise FinalAttestationContentOperationError("final attestation workspace must be absent or empty")
        return candidate
    try:
        os.mkdir(candidate, 0o700)
    except OSError as exc:
        raise FinalAttestationContentOperationError("unable to create final attestation workspace") from exc
    item = candidate.lstat()
    if not stat.S_ISDIR(item.st_mode):
        raise FinalAttestationContentOperationError("final attestation workspace changed type during creation")
    return candidate


def run_operation(run_verification: Path, workspace: Path, repository: str, gh: str) -> dict[str, Any]:
    receipt = _read_json_object(run_verification, label="final evaluator run verification receipt")
    artifact_id, head = validate_run_verification(receipt)
    root = _external_workspace(workspace)
    materializer = _load(MATERIALIZER_PATH, "psmatrix_final_attestation_materializer")
    verifier = _load(VERIFIER_PATH, "psmatrix_final_attestation_verifier")
    archive_root = Path(tempfile.mkdtemp(prefix="psmatrix-final-attestation-"))
    archive = archive_root / f"artifact-{artifact_id}.zip"
    bundle_root = root / "bundle"
    verification_path = root / "final-attestation-verification.json"
    try:
        try:
            materializer.download(gh, repository, artifact_id, archive)
            archive_sha = materializer._sha256(archive)
            extracted = materializer.safe_extract(archive, bundle_root)
        except Exception as exc:
            raise FinalAttestationContentOperationError(f"exact final-attestation artifact materialization failed: {exc}") from exc
        before_tree, before_files = _tree_state(bundle_root)
        if before_tree != extracted.get("tree_sha256") or len(before_files) != extracted.get("file_count"):
            raise FinalAttestationContentOperationError("safe extraction tree receipt mismatch")
        try:
            verification = verifier.verify(bundle_root, head)
        except Exception as exc:
            raise FinalAttestationContentOperationError(f"independent final-attestation semantic verification failed: {exc}") from exc
        if verification.get("schema") != 1 or verification.get("kind") != "psmatrix.final-ga-attestation-bundle-verification" or verification.get("version") != "2.0.0" or verification.get("status") != "PASS" or verification.get("final_ga_attestation_verified") is not True or verification.get("ga_eligible") is not True:
            raise FinalAttestationContentOperationError("independent final attestation verification did not prove GA eligibility")
        written_verification = _write_json_once(verification_path, verification, label="final attestation verification receipt")
        after_tree, after_files = _tree_state(bundle_root)
        if after_tree != before_tree or after_files != before_files:
            raise FinalAttestationContentOperationError("final attestation semantic verifier mutated materialized artifact tree")
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-content-operation",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": head,
            "evaluator_run_id": receipt["run_id"],
            "artifact": ARTIFACT,
            "artifact_id": artifact_id,
            "artifact_archive_sha256": archive_sha,
            "materialized_file_count": len(before_files),
            "materialized_tree_sha256": before_tree,
            "verification_receipt": str(written_verification),
            "verification_receipt_sha256": _sha256(written_verification),
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
        written = _write_json_once(args.output, value, label="final attestation content operation output")
        print(f"final_ga_attestation_content_operation=PASS run={value['evaluator_run_id']} artifact_id={value['artifact_id']}")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print(f"output={written}")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, FinalAttestationContentOperationError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA attestation content operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())