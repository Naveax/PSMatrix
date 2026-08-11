from __future__ import annotations

import argparse
import json
import os
import re
import stat
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
SHA40 = re.compile(r"^[0-9a-f]{40}$")
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


def repository_head(root: Path, git: str) -> str:
    completed = subprocess.run(
        [git, "-C", str(root), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RepositoryPrivateMaterialScanError(
            f"git rev-parse HEAD failed: {completed.stderr.strip()}"
        )
    head = completed.stdout.strip().lower()
    if SHA40.fullmatch(head) is None:
        raise RepositoryPrivateMaterialScanError(
            "repository HEAD is not an exact lowercase 40-hex commit"
        )
    return head


def _reject_symlink_components(path: Path, label: str) -> None:
    expanded = path.expanduser()
    parts = expanded.parts
    if expanded.is_absolute():
        current = Path(expanded.anchor)
        start = 1
    else:
        current = Path(".")
        start = 0
    for part in parts[start:]:
        current = current / part
        if current.is_symlink():
            raise RepositoryPrivateMaterialScanError(
                f"{label} may not traverse a symlink component"
            )


def _write_private_material_scan_receipt(path: Path, value: dict[str, Any]) -> Path:
    _reject_symlink_components(path, "private-material scan output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise RepositoryPrivateMaterialScanError(
            "private-material scan output must not already exist"
        )
    parent = absolute.parent
    _reject_symlink_components(parent, "private-material scan output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise RepositoryPrivateMaterialScanError(
            "private-material scan output parent must already exist"
        )
    candidate = resolved_parent / absolute.name

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise RepositoryPrivateMaterialScanError(
            "private-material scan output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise RepositoryPrivateMaterialScanError(
            f"private-material scan output could not be created: {exc}"
        ) from exc

    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    handle = None
    success = False
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise RepositoryPrivateMaterialScanError(
                "private-material scan output path does not name the exclusively created file"
            )
        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise RepositoryPrivateMaterialScanError(
                "private-material scan output read-back verification failed"
            )
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise RepositoryPrivateMaterialScanError(
                "private-material scan output path identity changed during write"
            )
        success = True
        return candidate
    finally:
        if handle is not None:
            handle.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail closed on tracked private-key material and high-confidence GitHub tokens without emitting secret values")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--git", default="git")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        root = args.root.expanduser().resolve()
        head = repository_head(root, args.git)
        value = scan(root, tracked_files(root, args.git))
        value["repository_head"] = head
        if args.output is not None:
            _write_private_material_scan_receipt(args.output, value)
        print(f"repository_private_material_scan={value['status']} files={value['tracked_file_count']} findings={value['finding_count']}")
        print(f"repository_head={value['repository_head']}")
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
