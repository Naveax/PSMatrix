from __future__ import annotations

from pathlib import PurePosixPath

_INSTALLED = False
_WINDOWS_FORBIDDEN = set('<>:"|?*')
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CLOCK$",
    "CONIN$",
    "CONOUT$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    "COM¹",
    "COM²",
    "COM³",
    "LPT¹",
    "LPT²",
    "LPT³",
}


def _segment_device_stem(segment: str) -> str:
    return segment.split(".", 1)[0].rstrip(" .").upper()


def _hardened_safe_relative(value: str) -> PurePosixPath:
    from . import http_sessions as sessions

    if not isinstance(value, str) or not value or len(value) > 4096:
        raise sessions.SessionError("Project path is invalid")
    if "\\" in value or value.startswith("/"):
        raise sessions.SessionError("Project path is invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise sessions.SessionError("Project path contains a control character")

    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise sessions.SessionError("Project path contains an invalid segment")

    for segment in segments:
        if len(segment) > 255:
            raise sessions.SessionError("Project path segment is too long")
        if segment.endswith((" ", ".")):
            raise sessions.SessionError("Project path segment has an unsafe trailing character")
        if any(ch in _WINDOWS_FORBIDDEN for ch in segment):
            raise sessions.SessionError("Project path contains a Windows-unsafe character")
        if _segment_device_stem(segment) in _WINDOWS_RESERVED:
            raise sessions.SessionError("Project path contains a reserved Windows device name")

    pure = PurePosixPath(*segments)
    if pure.is_absolute() or not pure.parts or tuple(pure.parts) != tuple(segments):
        raise sessions.SessionError("Project path is not canonical")
    return pure


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_project_path_grammar_hardened", False):
        _INSTALLED = True
        return

    sessions._safe_relative = _hardened_safe_relative
    sessions._project_path_grammar_hardened = True
    _INSTALLED = True
