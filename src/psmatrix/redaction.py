from __future__ import annotations

import base64
import json
from dataclasses import fields, is_dataclass, replace
from typing import Any, Iterable

from .models import ExecutionResult

_REDACTED = "<PSMATRIX_REDACTED>"


class SecretRedactor:
    """Exact-value redaction for user-supplied inputs and their common encodings.

    The redactor is intentionally deterministic and does not attempt heuristic secret
    discovery. It protects values that PSMatrix itself injected into a child process.
    """

    def __init__(self, values: Iterable[str | bytes]) -> None:
        tokens: set[str] = set()
        short_tokens: set[str] = set()
        for value in values:
            raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            if len(text) >= 4:
                tokens.add(text)
            else:
                short_tokens.add(text)
            encoded = base64.b64encode(raw).decode("ascii")
            url_encoded = base64.urlsafe_b64encode(raw).decode("ascii")
            hex_encoded = raw.hex()
            for candidate in (encoded, url_encoded, hex_encoded):
                if len(candidate) >= 8:
                    tokens.add(candidate)
        self._tokens = tuple(sorted(tokens, key=len, reverse=True))
        self._short_tokens = tuple(sorted(short_tokens, key=len, reverse=True))

    @classmethod
    def from_profile(cls, profile: Any) -> "SecretRedactor":
        values: list[str | bytes] = []
        values.extend(str(value) for value in getattr(profile, "arguments", []))
        values.extend(str(value) for value in getattr(profile, "parameters", {}).values())
        values.extend(str(value) for value in getattr(profile, "environment", {}).values())
        stdin_data = getattr(profile, "stdin_data", None)
        if stdin_data:
            values.append(stdin_data)
        return cls(values)

    def text(self, value: str) -> str:
        result = value
        for token in self._tokens:
            result = result.replace(token, _REDACTED)
        if self._short_tokens:
            lines = result.splitlines(keepends=True)
            for index, line in enumerate(lines):
                content = line.rstrip("\r\n")
                ending = line[len(content) :]
                if content in self._short_tokens:
                    lines[index] = _REDACTED + ending
            result = "".join(lines)
        return result

    def execution(self, result: ExecutionResult) -> ExecutionResult:
        return replace(result, stdout=self.text(result.stdout), stderr=self.text(result.stderr))

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.value(item) for item in value)
        if isinstance(value, dict):
            return {key: self.value(item) for key, item in value.items()}
        if is_dataclass(value) and not isinstance(value, type):
            updates = {item.name: self.value(getattr(value, item.name)) for item in fields(value)}
            return replace(value, **updates)
        return value

    def contains_secret(self, payload: Any) -> bool:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return any(token and token in raw for token in (*self._tokens, *self._short_tokens))
