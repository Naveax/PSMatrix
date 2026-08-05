from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import zipfile
from pathlib import Path

from .models import MatrixReport
from .sbom import build_sbom
from .util import sha256_file


def _git_commit(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            text=True,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _zip_write(zf: zipfile.ZipFile, name: str, data: bytes) -> dict:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)
    return {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_evidence_bundle(report: MatrixReport, path: Path, *, project_root: Path) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    provenance = {
        "schema": 1,
        "created_at": report.finished_at,
        "tool": {"name": "PSMatrix", "version": report.tool_version},
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "git_commit": _git_commit(project_root),
        "matrix_status": report.status,
        "sources": [
            {"path": target.source, "sha256": target.source_sha256, "runtime": target.runtime_id}
            for target in report.targets
        ],
    }
    entries: list[dict] = []
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as zf:
            entries.append(
                _zip_write(
                    zf,
                    "matrix-report.json",
                    json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
                )
            )
            entries.append(
                _zip_write(
                    zf,
                    "provenance.json",
                    json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
                )
            )
            entries.append(
                _zip_write(
                    zf,
                    "sbom.cdx.json",
                    json.dumps(build_sbom(report), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
                )
            )
            seen: set[str] = set()
            for target in report.targets:
                source = Path(target.source)
                if not source.is_file() or target.source_sha256 in seen:
                    continue
                actual_hash = sha256_file(source)
                if actual_hash != target.source_sha256:
                    raise ValueError(
                        f"Source changed after validation: {source} expected {target.source_sha256} got {actual_hash}"
                    )
                seen.add(target.source_sha256)
                entries.append(
                    _zip_write(
                        zf,
                        f"sources/{target.source_sha256}-{source.name}",
                        source.read_bytes(),
                    )
                )
            manifest = {"schema": 1, "entries": sorted(entries, key=lambda item: item["path"])}
            _zip_write(
                zf,
                "manifest.json",
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
            )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
