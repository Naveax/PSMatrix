from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .models import FileChange


_REPARSE_POINT = 0x400


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _metadata(info: os.stat_result, *, kind: str | None = None) -> dict[str, object]:
    item: dict[str, object] = {
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
    }
    if kind is not None:
        item["kind"] = kind
    return item


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    try:
        return os.path.samestat(left, right)
    except (AttributeError, OSError, ValueError):
        return (
            getattr(left, "st_dev", None) == getattr(right, "st_dev", None)
            and getattr(left, "st_ino", None) == getattr(right, "st_ino", None)
            and getattr(left, "st_ino", 0) not in {0, None}
        )


def _same_version(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_file(left, right)
        and int(left.st_size) == int(right.st_size)
        and int(left.st_mtime_ns) == int(right.st_mtime_ns)
    )


def _snapshot_regular_file(
    path: Path,
    initial: os.stat_result,
    *,
    max_file_size: int,
) -> dict[str, object]:
    item = _metadata(initial)
    if int(initial.st_size) > max_file_size:
        return item

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            opened = os.fstat(handle.fileno())
            current = path.lstat()
            if (
                _is_link_or_reparse(current)
                or not stat.S_ISREG(current.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or not _same_file(current, opened)
            ):
                return _metadata(current, kind="unstable")

            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)

            opened_after = os.fstat(handle.fileno())
            current_after = path.lstat()
            if (
                _is_link_or_reparse(current_after)
                or not stat.S_ISREG(current_after.st_mode)
                or not _same_version(opened, opened_after)
                or not _same_file(current_after, opened_after)
            ):
                return _metadata(current_after, kind="unstable")

            item = _metadata(opened_after)
            item["sha256"] = digest.hexdigest()
            return item
    except (FileNotFoundError, NotADirectoryError):
        return _metadata(initial, kind="unavailable")
    except OSError:
        return _metadata(initial, kind="unavailable")
    finally:
        if fd is not None:
            os.close(fd)


def snapshot_tree(
    root: Path,
    max_file_size: int = 64 * 1024 * 1024,
    excluded_roots: set[str] | frozenset[str] | None = None,
) -> dict[str, dict[str, object]]:
    root = root.resolve()
    excluded = excluded_roots or set()
    result: dict[str, dict[str, object]] = {}

    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        dirnames.sort()
        filenames.sort()

        for name in list(dirnames):
            path = current / name
            relative_path = path.relative_to(root)
            if relative_path.parts and relative_path.parts[0] in excluded:
                dirnames.remove(name)
                continue
            try:
                info = path.lstat()
            except OSError:
                dirnames.remove(name)
                continue
            if _is_link_or_reparse(info):
                result[relative_path.as_posix()] = _metadata(info, kind="indirect")
                dirnames.remove(name)
            elif not stat.S_ISDIR(info.st_mode):
                result[relative_path.as_posix()] = _metadata(info, kind="special")
                dirnames.remove(name)

        for name in filenames:
            path = current / name
            relative_path = path.relative_to(root)
            if relative_path.parts and relative_path.parts[0] in excluded:
                continue
            relative = relative_path.as_posix()
            try:
                info = path.lstat()
            except OSError:
                continue
            if _is_link_or_reparse(info):
                result[relative] = _metadata(info, kind="indirect")
            elif stat.S_ISREG(info.st_mode):
                result[relative] = _snapshot_regular_file(
                    path,
                    info,
                    max_file_size=max_file_size,
                )
            else:
                result[relative] = _metadata(info, kind="special")

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
