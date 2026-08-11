from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK_SIZE = 1024 * 1024
_OVERLAP = max(len(marker) for marker in PRIVATE_MARKERS) - 1


def _scan_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    carry = b""
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            window = carry + chunk
            if any(marker in window for marker in PRIVATE_MARKERS):
                raise RuntimeError(f"Private key material exists in evidence file: {path}")
            carry = window[-_OVERLAP:] if _OVERLAP else b""
    return digest.hexdigest(), size


def scan_tree(root: Path) -> dict[str, Any]:
    base = root.resolve()
    if not base.is_dir():
        raise RuntimeError(f"Evidence tree does not exist: {base}")
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted((item for item in base.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        digest, size = _scan_file(path)
        relative = path.relative_to(base).as_posix()
        rows.append({"path": relative, "sha256": digest, "size": size})
        total_bytes += size
    if not rows:
        raise RuntimeError(f"Evidence tree contains no files: {base}")
    manifest_bytes = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "schema": 1,
        "kind": "psmatrix.private-key-material-streaming-scan",
        "status": "PASS",
        "root": str(base),
        "file_count": len(rows),
        "byte_count": total_bytes,
        "tree_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "private_key_markers_found": 0,
        "size_limit_applied": False,
        "chunk_size": _CHUNK_SIZE,
        "files": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Stream-scan every evidence byte for private-key PEM markers")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = scan_tree(args.root)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise RuntimeError(f"Refusing to overwrite streaming scan report: {output}")
        output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
