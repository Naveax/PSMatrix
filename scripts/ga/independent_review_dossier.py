#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from psmatrix.release import verify_release_manifest
from psmatrix.util import sha256_file


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^2\.0\.0(?:rc[0-9]+)?$")
REQUIRED_SECTIONS = (
    "architecture",
    "authentication",
    "authorization",
    "sandbox",
    "supply-chain",
    "recovery",
    "operations",
    "privacy",
    "release-process",
)
REQUIRED_METHODS = (
    "architecture-review",
    "threat-model-review",
    "manual-code-review",
    "test-evidence-review",
)


class DossierError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or verify a deterministic PSMatrix independent-review dossier.")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--release-manifest", type=Path, required=True)
    build.add_argument("--artifact-dir", type=Path, required=True)
    build.add_argument("--release-public-key", type=Path, required=True)
    build.add_argument("--release-commit", required=True)
    build.add_argument("--output-dir", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--dossier", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser.parse_args()


def atomic_json(path: Path, value: Any) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=str(destination.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def exact_commit(value: str) -> str:
    text = str(value).lower()
    if COMMIT_RE.fullmatch(text) is None:
        raise DossierError("release_commit must be a full 40-character Git SHA")
    return text


def load_object(path: Path, label: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise DossierError(f"{label} is missing or unsafe")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DossierError(f"{label} root must be an object")
    return value


def select_release_artifacts(manifest_path: Path, artifact_dir: Path) -> dict[str, dict[str, Any]]:
    payload = load_object(manifest_path, "release manifest")
    manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else None
    if manifest is None:
        raise DossierError("release manifest payload is malformed")
    version = str(manifest.get("version") or "")
    if VERSION_RE.fullmatch(version) is None:
        raise DossierError("release version must be 2.0.0 or 2.0.0rcN")
    rows = manifest.get("artifacts")
    if not isinstance(rows, list):
        raise DossierError("release manifest artifacts are missing")

    selected: dict[str, list[dict[str, Any]]] = {"source": [], "wheel": []}
    for row in rows:
        if not isinstance(row, dict):
            raise DossierError("release artifact metadata is malformed")
        name = str(row.get("name") or "")
        digest = str(row.get("sha256") or "").lower()
        size = row.get("size")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise DossierError("release artifact digest is invalid")
        record = {"name": name, "sha256": digest, "size": size}
        if name.endswith("-source.zip"):
            selected["source"].append(record)
        if name.endswith(".whl"):
            selected["wheel"].append(record)

    if len(selected["source"]) != 1:
        raise DossierError("release manifest must contain exactly one source ZIP")
    if len(selected["wheel"]) != 1:
        raise DossierError("release manifest must contain exactly one wheel")

    for record in (selected["source"][0], selected["wheel"][0]):
        path = artifact_dir.resolve() / record["name"]
        if not path.is_file() or path.is_symlink():
            raise DossierError(f"release artifact is missing or unsafe: {record['name']}")
        if path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
            raise DossierError(f"release artifact digest mismatch: {record['name']}")
    return {
        "version": {"value": version},
        "source": selected["source"][0],
        "wheel": selected["wheel"][0],
    }


def report_template(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "psmatrix.independent-security-review-report",
        "status": "INCOMPLETE",
        "reviewed_commit": binding["release_commit"],
        "reviewed_version": binding["release_version"],
        "reviewed_release_sha256": binding["release_manifest_sha256"],
        "reviewed_source_sha256": binding["source"]["sha256"],
        "reviewer": {
            "name": "",
            "organization": "",
            "role": "",
            "contact": "",
            "conflict_of_interest": None,
            "key_controlled_by_reviewer": None,
        },
        "review_hours": 0,
        "methodologies": list(REQUIRED_METHODS),
        "sections": [
            {"id": section, "status": "NOT_REVIEWED", "summary": "", "evidence": []}
            for section in REQUIRED_SECTIONS
        ],
        "findings": [],
        "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "conclusion": "",
    }


def deterministic_zip(root: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            if not path.is_file() or path == output:
                continue
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def build(args: argparse.Namespace) -> int:
    commit = exact_commit(args.release_commit)
    manifest_path = args.release_manifest.resolve()
    artifact_dir = args.artifact_dir.resolve()
    public_key = args.release_public_key.resolve()
    if not artifact_dir.is_dir() or not public_key.is_file() or public_key.is_symlink():
        raise DossierError("release artifact directory or public key is missing")

    verified = verify_release_manifest(manifest_path, artifact_dir, signing_public_key=public_key)
    if verified.get("valid") is not True or not isinstance(verified.get("signature"), dict):
        raise DossierError("signed release manifest verification failed")
    selected = select_release_artifacts(manifest_path, artifact_dir)

    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise DossierError("output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)

    release_copy = output / "release-manifest.json"
    source_copy = output / selected["source"]["name"]
    wheel_metadata = output / "wheel-metadata.json"
    shutil.copyfile(manifest_path, release_copy)
    shutil.copyfile(artifact_dir / selected["source"]["name"], source_copy)

    binding = {
        "schema": 1,
        "kind": "psmatrix.independent-review-release-binding",
        "release_commit": commit,
        "release_version": selected["version"]["value"],
        "release_manifest": release_copy.name,
        "release_manifest_sha256": sha256_file(release_copy),
        "source": {
            "name": source_copy.name,
            "sha256": sha256_file(source_copy),
            "size": source_copy.stat().st_size,
        },
        "wheel": selected["wheel"],
        "required_sections": list(REQUIRED_SECTIONS),
        "required_methodologies": list(REQUIRED_METHODS),
        "completion": {
            "independent_review": True,
            "conflict_of_interest": False,
            "key_controlled_by_reviewer": True,
            "critical_findings": 0,
            "high_findings": 0,
        },
    }
    atomic_json(output / "release-binding.json", binding)
    atomic_json(wheel_metadata, selected["wheel"])
    atomic_json(output / "review-report.template.json", report_template(binding))

    inventory_rows = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.is_file():
            inventory_rows.append({"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size})
    dossier_manifest = {
        "schema": 1,
        "kind": "psmatrix.independent-review-dossier",
        "status": "READY_FOR_REVIEWER",
        "release_commit": commit,
        "release_version": binding["release_version"],
        "files": inventory_rows,
        "private_keys_included": False,
        "ga_eligible": False,
    }
    atomic_json(output / "dossier-manifest.json", dossier_manifest)
    archive = output / "psmatrix-independent-review-dossier.zip"
    deterministic_zip(output, archive)
    result = {
        **dossier_manifest,
        "archive": {"name": archive.name, "sha256": sha256_file(archive), "size": archive.stat().st_size},
    }
    atomic_json(output / "dossier-status.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def verify(args: argparse.Namespace) -> int:
    dossier = args.dossier.resolve()
    if not dossier.is_dir() or dossier.is_symlink():
        raise DossierError("dossier directory is missing or unsafe")
    manifest = load_object(dossier / "dossier-manifest.json", "dossier manifest")
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.independent-review-dossier":
        raise DossierError("dossier manifest schema is invalid")
    if manifest.get("status") != "READY_FOR_REVIEWER" or manifest.get("private_keys_included") is not False:
        raise DossierError("dossier is not safe for reviewer delivery")
    commit = exact_commit(str(manifest.get("release_commit") or ""))
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise DossierError("dossier inventory is missing")
    for row in rows:
        if not isinstance(row, dict):
            raise DossierError("dossier inventory row is invalid")
        name = str(row.get("name") or "")
        if Path(name).name != name:
            raise DossierError("dossier inventory name is unsafe")
        path = dossier / name
        if not path.is_file() or path.is_symlink():
            raise DossierError(f"dossier file is missing or unsafe: {name}")
        if path.stat().st_size != row.get("size") or sha256_file(path) != row.get("sha256"):
            raise DossierError(f"dossier file digest mismatch: {name}")
    binding = load_object(dossier / "release-binding.json", "release binding")
    if binding.get("release_commit") != commit:
        raise DossierError("dossier release binding commit mismatch")
    result = {
        "schema": 1,
        "kind": "psmatrix.independent-review-dossier-verification",
        "status": "PASS",
        "release_commit": commit,
        "release_version": binding.get("release_version"),
        "file_count": len(rows),
        "ga_eligible": False,
    }
    if args.output:
        atomic_json(args.output.resolve(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    args = parse_args()
    return build(args) if args.command == "build" else verify(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DossierError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"independent review dossier failed: {exc}")
