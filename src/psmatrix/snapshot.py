from __future__ import annotations

from pathlib import Path

from .models import FileChange
from .util import sha256_file


def snapshot_tree(
    root: Path,
    max_file_size: int = 64 * 1024 * 1024,
    excluded_roots: set[str] | frozenset[str] | None = None,
) -> dict[str, dict[str, object]]:
    root = root.resolve()
    excluded = excluded_roots or set()
    result: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(root)
        if relative_path.parts and relative_path.parts[0] in excluded:
            continue
        relative = relative_path.as_posix()
        stat = path.stat()
        item: dict[str, object] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        if stat.st_size <= max_file_size:
            item["sha256"] = sha256_file(path)
        result[relative] = item
    return result


def diff_snapshots(
    before: dict[str, dict[str, object]], after: dict[str, dict[str, object]]
) -> list[FileChange]:
    changes: list[FileChange] = []
    for path in sorted(before.keys() | after.keys()):
        old = before.get(path)
        new = after.get(path)
        if old is None and new is not None:
            changes.append(
                FileChange(
                    path=path,
                    change="created",
                    size_after=int(new["size"]),
                    sha256_after=new.get("sha256") if isinstance(new.get("sha256"), str) else None,
                )
            )
        elif new is None and old is not None:
            changes.append(
                FileChange(
                    path=path,
                    change="deleted",
                    size_before=int(old["size"]),
                    sha256_before=old.get("sha256") if isinstance(old.get("sha256"), str) else None,
                )
            )
        elif old != new and old is not None and new is not None:
            changes.append(
                FileChange(
                    path=path,
                    change="modified",
                    size_before=int(old["size"]),
                    size_after=int(new["size"]),
                    sha256_before=old.get("sha256") if isinstance(old.get("sha256"), str) else None,
                    sha256_after=new.get("sha256") if isinstance(new.get("sha256"), str) else None,
                )
            )
    return changes
