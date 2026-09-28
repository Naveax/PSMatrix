from __future__ import annotations

from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_SAFE_ARCHIVE_PARTS: Callable[[str], tuple[str, ...]] | None = None

# Win32 treats the ISO-8859-1 superscript digits as valid COM#/LPT# device
# numbers too. CONIN$/CONOUT$ are console device names accepted by CreateFile.
_EXTRA_RESERVED_BASES = frozenset(
    {
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
        "CONIN$",
        "CONOUT$",
    }
)
_WIN32_FORBIDDEN_CHARACTERS = frozenset('<>"|?*')


def _validate_win32_component(rw: Any, component: str, filename: str) -> None:
    if any(character in _WIN32_FORBIDDEN_CHARACTERS for character in component):
        raise rw.WorkerError(f"Windows-unsafe worker artifact path: {filename}")
    if any(ord(character) < 32 for character in component):
        raise rw.WorkerError(f"Windows control character in worker artifact path: {filename}")
    base = component.split(".", 1)[0].upper()
    if base in _EXTRA_RESERVED_BASES:
        raise rw.WorkerError(f"Reserved Windows device path in worker artifact: {filename}")


def install() -> None:
    global _INSTALLED, _ORIGINAL_SAFE_ARCHIVE_PARTS
    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_windows_archive_path_hardened", False):
        _INSTALLED = True
        return

    original = rw._safe_archive_parts
    _ORIGINAL_SAFE_ARCHIVE_PARTS = original

    def safe_archive_parts(filename: str) -> tuple[str, ...]:
        # Preserve the canonical path/traversal checks first, then add Win32
        # namespace rules that are not represented by ordinary Path semantics.
        parts = original(filename)
        for component in parts:
            _validate_win32_component(rw, component, filename)
        return parts

    rw._safe_archive_parts = safe_archive_parts
    rw._windows_archive_path_hardened = True
    _INSTALLED = True
