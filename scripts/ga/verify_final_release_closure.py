from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

_IMPL_PATH = Path(__file__).with_name("_verify_final_release_closure_impl.py")


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_verification_impl",
        _IMPL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load final release closure implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_original_verify = _impl.verify


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
            raise FinalReleaseClosureError(f"{label} may not traverse a symlink component")


def _read(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FinalReleaseClosureError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FinalReleaseClosureError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FinalReleaseClosureError(f"{label} root must be object")
    return value


def verify(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    documentation: dict[str, Any],
    cleanup: dict[str, Any],
    final_scan: dict[str, Any],
) -> dict[str, Any]:
    if immutable_release.get(
        "publication_receipt_output_reserved_before_mutation"
    ) is not True:
        raise FinalReleaseClosureError(
            "immutable release verification does not prove publication receipt output reservation before mutation"
        )
    value = _original_verify(
        release_closure,
        immutable_release,
        documentation,
        cleanup,
        final_scan,
    )
    if not isinstance(value, dict):
        raise FinalReleaseClosureError(
            "final release closure implementation returned an invalid receipt"
        )
    result = dict(value)
    result["publication_receipt_output_reserved_before_mutation"] = True
    return result


_impl.verify = verify
_impl._reject_symlink_components = _reject_symlink_components
_impl._read = _read


def main() -> int:
    return _impl.main()


if __name__ == "__main__":
    raise SystemExit(main())
