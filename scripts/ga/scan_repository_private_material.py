from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

PEM_PRIVATE_BLOCK = re.compile(
    rb"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----[\r\n]+"
    rb"(?P<body>[A-Za-z0-9+/=\r\n]{64,})"
    rb"-----END (?P=label)-----"
)
GITHUB_CLASSIC_TOKEN = re.compile(rb"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])")
GITHUB_FINE_GRAINED_TOKEN = re.compile(rb"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{50,255}(?![A-Za-z0-9_])")
FORBIDDEN_PRIVATE_CONTAINER_SUFFIXES = {".p12", ".pfx"}
FORBIDDEN_PRIVATE_KEY_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
MAX_TRACKED_FILE_BYTES = 100 * 1024 * 1024


class RepositoryPrivateMaterialScanError(RuntimeError):
    pass


def classify(path: Path, data: bytes) -> list[str]:
    findings: list[str] = []
    lower_name = path.name.lower()
    if path.suffix.lower() in FORBIDDEN_PRIVATE_CONTAINER_SUFFIXES:
        findings.append("tracked-private-key-container")
    if lower_name in FORBIDDEN_PRIVATE_KEY_FILENAMES:
        findings.append("tracked-private-key-filename")
    if PEM_PRIVATE_BLOCK.search(data):
        findings.append("private-key-pem-block")
    if GITHUB_CLASSIC_TOKEN.search(data):
        findings.append("github-classic-token")
    if GITHUB_FINE_GRAINED_TOKEN.search(data):
        findings.append("github-fine-grained-token")
    return findings


def scan(root: Path, tracked_paths: Iterable[str]) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise RepositoryPrivateMaterialScanError("repository root is missing")
    findings: list[dict[str, str]] = []
    scanned = 0
    for relative in tracked_paths:
        if not relative or "\x00" in relative:
            raise RepositoryPrivateMaterialScanError("invalid tracked path")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise RepositoryPrivateMaterialScanError(f"tracked path escapes repository: {relative}") from exc
        if not path.is_file():
            raise RepositoryPrivateMaterialScanError(f"tracked file is missing from working tree: {relative}")
        size = path.stat().st_size
        if size > MAX_TRACKED_FILE_BYTES:
            raise RepositoryPrivateMaterialScanError(f"tracked file exceeds bounded scan size: {relative}")
        data = path.read_bytes()
        scanned += 1
        for finding_type in classify(Path(relative), data):
            findings.append({"path": relative.replace("\\", "/"), "type": finding_type})
    findings.sort(key=lambda item: (item["path"], item["type"]))
    return {
        "schema": 1,
        "kind": "psmatrix.repository-private-material-scan",
        "version": "2.0.0",
        "status": "PASS" if not findings else "FAIL",
        "tracked_file_count": scanned,
        "finding_count": len(findings),
        "findings": findings,
        "scanned_classes": [
            "private-key-pem-block",
            "tracked-private-key-container",
            "tracked-private-key-filename",
            "github-classic-token",
            "github-fine-grained-token",
        ],
        "secret_values_emitted": False,
        "secret_hashes_emitted": False,
        "secret_lengths_emitted": False,
        "ga_eligible": False,
    }


def tracked_files(root: Path, git: str) -> list[str]:
    completed = subprocess.run(
        [git, "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RepositoryPrivateMaterialScanError(
            f"git ls-files failed: {completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    try:
        decoded = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositoryPrivateMaterialScanError("git ls-files returned non-UTF-8 path data") from exc
    values = [value for value in decoded.split("\x00") if value]
    if not values:
        raise RepositoryPrivateMaterialScanError("repository has zero tracked files")
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail closed on tracked private-key material and high-confidence GitHub tokens without emitting secret values")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--git", default="git")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        root = args.root.expanduser().resolve()
        value = scan(root, tracked_files(root, args.git))
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"repository_private_material_scan={value['status']} files={value['tracked_file_count']} findings={value['finding_count']}")
        print("secret_values_emitted=false")
        print("secret_hashes_emitted=false")
        print("secret_lengths_emitted=false")
        print("ga_eligible=false")
        if value["status"] != "PASS":
            for item in value["findings"]:
                print(f"finding path={item['path']} type={item['type']}", file=sys.stderr)
            return 1
        return 0
    except (OSError, RepositoryPrivateMaterialScanError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"repository private-material scan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
