#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from psmatrix.ga import load_ga_policy
from psmatrix.util import atomic_write_json, read_json, sha256_file


ROOT = Path(__file__).resolve().parents[2]
LEGACY_OPERATOR = ROOT / "scripts" / "ga" / "final_ga_closure.py"
VERSION = "2.0.0"
SBOM_NAME = f"psmatrix-{VERSION}-sbom.cdx.json"
CHECKSUMS_NAME = f"psmatrix-{VERSION}-SHA256SUMS"
SIGNED_RELEASE_NAMES = {
    f"psmatrix-{VERSION}-py3-none-any.whl",
    f"psmatrix-{VERSION}-source.tar.gz",
    f"psmatrix-{VERSION}-source.zip",
    f"psmatrix-{VERSION}-windows-certification-kit.zip",
    f"psmatrix-{VERSION}-windows-provisioning-kit.zip",
    f"psmatrix-{VERSION}-windows-workers.zip",
}


class HardenedClosureError(RuntimeError):
    pass


def _load_legacy():
    spec = importlib.util.spec_from_file_location("psmatrix_final_ga_closure_legacy", LEGACY_OPERATOR)
    if spec is None or spec.loader is None:
        raise HardenedClosureError("could not load reviewed final GA closure operator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEGACY = _load_legacy()
LEGACY_BUILD_CLOSURE_STATEMENT = LEGACY.build_closure_statement


def _resolve(base: Path, value: Any, label: str, *, directory: bool = False) -> Path:
    text = str(value or "")
    if not text or "\x00" in text or len(text) > 4096:
        raise HardenedClosureError(f"{label} path is missing or invalid")
    supplied = Path(text)
    path = (supplied if supplied.is_absolute() else base / supplied).resolve()
    base_resolved = base.resolve()
    try:
        relative = path.relative_to(base_resolved)
    except ValueError as exc:
        raise HardenedClosureError(f"{label} escapes the policy root") from exc
    cursor = base_resolved
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise HardenedClosureError(f"{label} traverses a symlink")
    if directory:
        if not path.is_dir():
            raise HardenedClosureError(f"{label} directory is missing")
    elif not path.is_file():
        raise HardenedClosureError(f"{label} file is missing")
    return path


def _release_record(policy: dict[str, Any]) -> dict[str, Any]:
    evidence = policy.get("evidence") if isinstance(policy.get("evidence"), dict) else {}
    record = evidence.get("signed-release")
    if not isinstance(record, dict):
        raise HardenedClosureError("GA policy signed-release evidence record is missing")
    if record.get("authority") != "release":
        raise HardenedClosureError("GA policy signed-release evidence authority is not release")
    return record


def _signed_release_inventory(policy: dict[str, Any], base: Path) -> dict[str, Any]:
    record = _release_record(policy)
    manifest_path = _resolve(base, record.get("manifest"), "signed release manifest")
    artifact_dir = _resolve(base, record.get("artifact_dir"), "signed release artifact root", directory=True)
    root = read_json(manifest_path)
    manifest = root.get("manifest") if isinstance(root, dict) and isinstance(root.get("manifest"), dict) else None
    if (
        manifest is None
        or manifest.get("schema") != 1
        or manifest.get("kind") != "psmatrix.release-manifest"
        or manifest.get("version") != VERSION
    ):
        raise HardenedClosureError("signed release manifest identity is not final PSMatrix 2.0.0")
    raw_items = manifest.get("artifacts")
    if not isinstance(raw_items, list) or len(raw_items) != 6:
        raise HardenedClosureError("protected final release manifest must contain exactly six signed distribution artifacts")

    items: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            raise HardenedClosureError("signed release artifact metadata is malformed")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = item.get("size")
        if Path(name).name != name or not name or LEGACY.SHA256_RE.fullmatch(digest) is None:
            raise HardenedClosureError("signed release artifact identity is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise HardenedClosureError(f"signed release artifact size is invalid: {name}")
        if name.casefold() in {existing.casefold() for existing in items}:
            raise HardenedClosureError("signed release artifact names are duplicated")
        path = artifact_dir / name
        if not path.is_file() or path.is_symlink():
            raise HardenedClosureError(f"signed release artifact is missing or unsafe: {name}")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise HardenedClosureError(f"signed release artifact digest mismatch: {name}")
        items[name] = {"name": name, "sha256": digest, "size": size, "path": path}
    if set(items) != SIGNED_RELEASE_NAMES:
        raise HardenedClosureError(
            f"protected final release artifact set mismatch: expected={sorted(SIGNED_RELEASE_NAMES)}, observed={sorted(items)}"
        )
    return {
        "manifest_path": manifest_path,
        "manifest_sha256": sha256_file(manifest_path),
        "artifact_dir": artifact_dir,
        "items": items,
    }


def _sbom_document(inventory: dict[str, Any]) -> dict[str, Any]:
    items = inventory["items"]
    wheel = items[f"psmatrix-{VERSION}-py3-none-any.whl"]
    manifest_sha = inventory["manifest_sha256"]
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://psmatrix.dev/release/{VERSION}/{manifest_sha}")
    components = []
    for name in sorted(items):
        item = items[name]
        components.append(
            {
                "type": "file",
                "name": name,
                "version": VERSION,
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "psmatrix",
                "version": VERSION,
                "hashes": [{"alg": "SHA-256", "content": wheel["sha256"]}],
                "properties": [
                    {"name": "psmatrix:release-manifest-sha256", "value": manifest_sha},
                    {"name": "psmatrix:signed-release-artifact-count", "value": "6"},
                    {"name": "psmatrix:closure-metadata-authority", "value": "final-ga-signer"},
                ],
            }
        },
        "components": components,
        "dependencies": [],
    }


def _atomic_text(path: Path, text: str) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_exact_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise HardenedClosureError(f"closure metadata path cannot be a symlink: {path.name}")
    if path.exists():
        if read_json(path) != value:
            raise HardenedClosureError(f"existing closure metadata differs from deterministic value: {path.name}")
        return
    atomic_write_json(path, value)


def _write_exact_text(path: Path, value: str) -> None:
    if path.is_symlink():
        raise HardenedClosureError(f"closure metadata path cannot be a symlink: {path.name}")
    if path.exists():
        if path.read_text(encoding="utf-8") != value:
            raise HardenedClosureError(f"existing closure metadata differs from deterministic value: {path.name}")
        return
    _atomic_text(path, value)


def prepare_metadata_from_loaded_policy(
    policy: dict[str, Any],
    base: Path,
    expected_commit: str,
    receipt: Path | None = None,
) -> dict[str, Any]:
    commit = LEGACY.exact_commit(expected_commit)
    inventory = _signed_release_inventory(policy, base)
    artifact_dir = inventory["artifact_dir"]
    sbom_path = artifact_dir / SBOM_NAME
    checksums_path = artifact_dir / CHECKSUMS_NAME
    sbom = _sbom_document(inventory)
    _write_exact_json(sbom_path, sbom)

    checksum_rows = {name: item["sha256"] for name, item in inventory["items"].items()}
    checksum_rows[SBOM_NAME] = sha256_file(sbom_path)
    checksum_text = "".join(f"{checksum_rows[name]}  {name}\n" for name in sorted(checksum_rows))
    _write_exact_text(checksums_path, checksum_text)

    result = {
        "schema": 1,
        "kind": "psmatrix.final-ga-closure-metadata-preparation",
        "status": "PASS",
        "version": VERSION,
        "release_commit": commit,
        "release_manifest_sha256": inventory["manifest_sha256"],
        "signed_release_artifact_count": 6,
        "closure_metadata_artifact_count": 2,
        "sbom": {"name": SBOM_NAME, "sha256": sha256_file(sbom_path), "size": sbom_path.stat().st_size},
        "checksums": {"name": CHECKSUMS_NAME, "sha256": sha256_file(checksums_path), "size": checksums_path.stat().st_size},
        "release_authority_scope_unchanged": True,
        "closure_metadata_final_signer_binding_pending": True,
        "ga_eligible": False,
    }
    if receipt is not None:
        destination = receipt.resolve()
        if destination.exists() or destination.is_symlink():
            raise HardenedClosureError("closure metadata receipt output must not already exist")
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(destination, result)
    return result


def prepare_metadata(policy_path: Path, expected_commit: str, receipt: Path | None = None) -> dict[str, Any]:
    policy, base = load_ga_policy(policy_path.resolve())
    return prepare_metadata_from_loaded_policy(policy, base, expected_commit, receipt)


def _parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        match = LEGACY.CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise HardenedClosureError(f"SHA256SUMS line {index} is malformed")
        digest = match.group(1).lower()
        name = match.group(2).strip()
        if Path(name).name != name or name in result:
            raise HardenedClosureError("SHA256SUMS contains an unsafe or duplicate artifact name")
        result[name] = digest
    if not result:
        raise HardenedClosureError("SHA256SUMS is empty")
    return result


def validate_release_inventory(policy: dict[str, Any], base: Path) -> dict[str, Any]:
    inventory = _signed_release_inventory(policy, base)
    items = inventory["items"]
    artifact_dir = inventory["artifact_dir"]
    sbom_path = artifact_dir / SBOM_NAME
    checksums_path = artifact_dir / CHECKSUMS_NAME
    if not sbom_path.is_file() or sbom_path.is_symlink():
        raise HardenedClosureError("deterministic CycloneDX closure SBOM is missing or unsafe")
    if not checksums_path.is_file() or checksums_path.is_symlink():
        raise HardenedClosureError("deterministic closure SHA256SUMS is missing or unsafe")
    if read_json(sbom_path) != _sbom_document(inventory):
        raise HardenedClosureError("closure SBOM differs from deterministic signed-release derivation")

    checksum_values = _parse_checksums(checksums_path)
    expected_checksums = {name: item["sha256"] for name, item in items.items()}
    expected_checksums[SBOM_NAME] = sha256_file(sbom_path)
    if checksum_values != expected_checksums:
        raise HardenedClosureError(
            "closure SHA256SUMS does not exactly bind all six signed artifacts plus the deterministic SBOM"
        )

    public_items = [
        {"name": name, "sha256": item["sha256"], "size": item["size"]}
        for name, item in sorted(items.items())
    ]
    public_items.extend(
        [
            {"name": SBOM_NAME, "sha256": sha256_file(sbom_path), "size": sbom_path.stat().st_size},
            {"name": CHECKSUMS_NAME, "sha256": sha256_file(checksums_path), "size": checksums_path.stat().st_size},
        ]
    )
    return {
        "manifest_path": inventory["manifest_path"],
        "manifest_sha256": inventory["manifest_sha256"],
        "artifact_dir": artifact_dir,
        "artifacts": public_items,
        "signed_release_artifact_count": 6,
        "closure_metadata_count": 2,
        "source_zip": {k: items[f"psmatrix-{VERSION}-source.zip"][k] for k in ("name", "sha256", "size")},
        "source_tar_gz": {k: items[f"psmatrix-{VERSION}-source.tar.gz"][k] for k in ("name", "sha256", "size")},
        "wheel": {k: items[f"psmatrix-{VERSION}-py3-none-any.whl"][k] for k in ("name", "sha256", "size")},
        "sbom": {"name": SBOM_NAME, "sha256": sha256_file(sbom_path), "size": sbom_path.stat().st_size},
        "checksums": {"name": CHECKSUMS_NAME, "sha256": sha256_file(checksums_path), "size": checksums_path.stat().st_size},
    }


def _hardened_statement(**kwargs: Any) -> dict[str, Any]:
    statement = LEGACY_BUILD_CLOSURE_STATEMENT(**kwargs)
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else None
    if predicate is None:
        raise HardenedClosureError("legacy final closure statement is malformed")
    release = kwargs.get("release") if isinstance(kwargs.get("release"), dict) else {}
    if release.get("signed_release_artifact_count") != 6 or release.get("closure_metadata_count") != 2:
        raise HardenedClosureError("final closure release/metadata cardinality mismatch")
    if predicate.get("release_artifact_count") != 8:
        raise HardenedClosureError("final closure subject inventory must contain six signed artifacts plus two closure metadata files")
    predicate["signed_release_artifact_count"] = 6
    predicate["closure_metadata_artifact_count"] = 2
    predicate["closure_metadata_final_signer_bound"] = True
    predicate["release_authority_scope_unchanged"] = True
    return statement


LEGACY.validate_release_inventory = validate_release_inventory
LEGACY.build_closure_statement = _hardened_statement


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hardened PSMatrix 2.0.0 final GA closure controller")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare-metadata")
    prepare.add_argument("--policy", type=Path, required=True)
    prepare.add_argument("--expected-commit", required=True)
    prepare.add_argument("--receipt", type=Path)

    sign = sub.add_parser("sign")
    sign.add_argument("--policy", type=Path, required=True)
    sign.add_argument("--source-root", type=Path, required=True)
    sign.add_argument("--expected-commit", required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    sign.add_argument("--output-dir", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--source-root", type=Path, required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--evaluation", type=Path, required=True)
    verify.add_argument("--ga-attestation", type=Path, required=True)
    verify.add_argument("--closure-attestation", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "prepare-metadata":
        result = prepare_metadata(args.policy, args.expected_commit, args.receipt)
    elif args.command == "sign":
        result = LEGACY.sign_closure(args)
    else:
        result = LEGACY.verify_closure(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HardenedClosureError, LEGACY.ClosureError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"hardened final GA closure failed: {exc}")
