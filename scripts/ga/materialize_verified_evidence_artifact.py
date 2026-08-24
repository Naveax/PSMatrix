from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


class EvidenceArtifactMaterializationError(RuntimeError):
    pass


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _reject_symlink_components(path: Path, label: str) -> Path:
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise EvidenceArtifactMaterializationError(f"{label} contains a symlink component")
    return absolute


def _safe_input_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise EvidenceArtifactMaterializationError(f"{label} is missing or unsafe")
    return resolved


def _safe_output_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    if candidate.exists() and candidate.is_dir():
        raise EvidenceArtifactMaterializationError(f"{label} must be a file path")
    return candidate.resolve()


def _safe_output_directory(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise EvidenceArtifactMaterializationError(f"{label} must be a directory")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _row(api_verification: dict[str, Any], gate: str) -> dict[str, Any]:
    if api_verification.get("schema") != 1 or api_verification.get("kind") != "psmatrix.final-ga-evidence-api-verification" or api_verification.get("version") != "2.0.0" or api_verification.get("status") != "PASS" or api_verification.get("verified_gate_count") != 11:
        raise EvidenceArtifactMaterializationError("11/11 evidence API verification is required")
    rows = api_verification.get("gates")
    if not isinstance(rows, list) or len(rows) != 11:
        raise EvidenceArtifactMaterializationError("evidence API verification gate rows mismatch")
    matches = [item for item in rows if isinstance(item, dict) and item.get("gate") == gate]
    if len(matches) != 1:
        raise EvidenceArtifactMaterializationError(f"gate must resolve to exactly one API-verified artifact: {gate}")
    row = matches[0]
    if row.get("verified") is not True or type(row.get("run_id")) is not int or row["run_id"] <= 0 or type(row.get("artifact_id")) is not int or row["artifact_id"] <= 0 or not str(row.get("artifact") or ""):
        raise EvidenceArtifactMaterializationError(f"API-verified gate row is incomplete: {gate}")
    return row


def safe_extract(archive: Path, destination: Path) -> dict[str, Any]:
    destination = _safe_output_directory(destination, "artifact destination")
    if destination.exists():
        if any(destination.iterdir()):
            raise EvidenceArtifactMaterializationError("artifact destination must be absent or empty")
    else:
        destination.mkdir(parents=True)
    seen: set[str] = set()
    files: list[dict[str, Any]] = []
    with zipfile.ZipFile(archive, "r") as bundle:
        infos = bundle.infolist()
        if not infos:
            raise EvidenceArtifactMaterializationError("artifact archive is empty")
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            if not name or pure.is_absolute() or ".." in pure.parts or "" in pure.parts:
                raise EvidenceArtifactMaterializationError(f"unsafe artifact archive path: {name!r}")
            normalized = pure.as_posix().rstrip("/")
            if not normalized:
                continue
            if normalized in seen:
                raise EvidenceArtifactMaterializationError(f"duplicate artifact archive path: {normalized}")
            seen.add(normalized)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise EvidenceArtifactMaterializationError(f"symlink is forbidden in evidence artifact: {normalized}")
            target = destination.joinpath(*pure.parts).resolve()
            try:
                target.relative_to(destination)
            except ValueError as exc:
                raise EvidenceArtifactMaterializationError(f"artifact path escapes destination: {normalized}") from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info, "r") as source, target.open("xb") as sink:
                shutil.copyfileobj(source, sink, length=1024 * 1024)
            files.append({"path": normalized, "size": target.stat().st_size, "sha256": _sha256(target)})
    if not files:
        raise EvidenceArtifactMaterializationError("artifact archive contains no files")
    files.sort(key=lambda item: item["path"])
    tree_digest = hashlib.sha256()
    for item in files:
        tree_digest.update(f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8"))
    return {"file_count": len(files), "files": files, "tree_sha256": tree_digest.hexdigest()}


def download(gh: str, repository: str, artifact_id: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as sink:
        completed = subprocess.run(
            [gh, "api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip"],
            stdout=sink,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    if completed.returncode != 0:
        output.unlink(missing_ok=True)
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceArtifactMaterializationError(f"gh artifact download failed: {error}")
    if not output.is_file() or output.stat().st_size <= 0:
        raise EvidenceArtifactMaterializationError("downloaded artifact archive is empty")


def materialize(api_verification: dict[str, Any], gate: str, archive: Path, destination: Path) -> dict[str, Any]:
    row = _row(api_verification, gate)
    state = safe_extract(archive, destination)
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-artifact-materialization",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": api_verification.get("execution_head"),
        "gate": gate,
        "run_id": row["run_id"],
        "artifact": row["artifact"],
        "artifact_id": row["artifact_id"],
        "artifact_archive_sha256": _sha256(archive),
        "file_count": state["file_count"],
        "tree_sha256": state["tree_sha256"],
        "files": state["files"],
        "download_source": f"github-actions-artifact-id:{row['artifact_id']}",
        "path_traversal_rejected": True,
        "symlinks_rejected": True,
        "duplicate_paths_rejected": True,
        "content_semantics_verified": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Download and safely materialize one API-verified final GA evidence artifact")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args()
    archive: Path | None = None
    try:
        api_verification_path = _safe_input_file(args.api_verification, "API verification input")
        api_verification = json.loads(api_verification_path.read_text(encoding="utf-8"))
        row = _row(api_verification, args.gate)
        temp_root = Path(tempfile.mkdtemp(prefix="psmatrix-evidence-artifact-"))
        archive = temp_root / f"artifact-{row['artifact_id']}.zip"
        download(args.gh, args.repository, row["artifact_id"], archive)
        value = materialize(api_verification, args.gate, archive, args.destination)
        receipt = _safe_output_file(args.receipt, "materialization receipt")
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"evidence_artifact_materialization=PASS gate={args.gate} run={value['run_id']} artifact_id={value['artifact_id']} files={value['file_count']}")
        print("content_semantics_verified=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile, EvidenceArtifactMaterializationError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"evidence artifact materialization failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if archive is not None:
            shutil.rmtree(archive.parent, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())