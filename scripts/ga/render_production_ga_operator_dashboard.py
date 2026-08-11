from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = ROOT / "scripts" / "ga" / "build_production_ga_operator_dashboard.py"
KIND = "psmatrix.production-ga-operator-dashboard-input-manifest"
VERSION = "2.0.0"
REQUIRED_KEYS = ("inventory_audit", "readiness_summary")
OPTIONAL_KEYS = (
    "readiness_verification",
    "lock_verification",
    "evidence_api_verification",
    "content_closure",
    "content_plan",
    "public_auth_operation",
    "content_closure_verification",
    "evaluator_verification",
    "final_attestation_operation",
    "release_closure",
    "authority_escrow_operation",
    "immutable_release_verification",
    "documentation_verification",
    "cleanup_verification",
    "final_repository_scan",
    "final_release_verification",
)
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


class OperatorDashboardInputManifestError(RuntimeError):
    pass


def _load_dashboard():
    spec = importlib.util.spec_from_file_location("psmatrix_operator_dashboard_manifest_target", DASHBOARD_PATH)
    if spec is None or spec.loader is None:
        raise OperatorDashboardInputManifestError("unable to load repository-owned dashboard builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OperatorDashboardInputManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


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
            raise OperatorDashboardInputManifestError(
                f"{label} may not traverse a symlink component"
            )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise OperatorDashboardInputManifestError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise OperatorDashboardInputManifestError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise OperatorDashboardInputManifestError(f"{label} root must be object")
    return value


def _external_receipt_root(path: Path) -> Path:
    _reject_symlink_components(path, "receipt root")
    resolved = path.expanduser().resolve()
    repo = ROOT.resolve()
    if not resolved.is_dir():
        raise OperatorDashboardInputManifestError("receipt root is missing or unsafe")
    try:
        resolved.relative_to(repo)
    except ValueError:
        return resolved
    raise OperatorDashboardInputManifestError("receipt root must stay outside repository")


def _resolve_relative_file(root: Path, raw: Any, role: str) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise OperatorDashboardInputManifestError(f"manifest path is invalid: {role}")
    if "\\" in raw or raw.startswith("/") or WINDOWS_ABSOLUTE.match(raw):
        raise OperatorDashboardInputManifestError(f"manifest path must be relative POSIX syntax: {role}")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or pure.as_posix() != raw or any(part in ("", ".", "..") for part in pure.parts):
        raise OperatorDashboardInputManifestError(f"manifest path escapes or is non-canonical: {role}")

    lexical = root
    for part in pure.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise OperatorDashboardInputManifestError(f"receipt path traverses a symlink: {role}")
    candidate = lexical.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise OperatorDashboardInputManifestError(f"manifest path escapes receipt root: {role}") from exc
    if not candidate.is_file():
        raise OperatorDashboardInputManifestError(f"receipt file is missing or unsafe: {role}")
    return candidate


def _validate_manifest(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    if value.get("schema") != 1 or value.get("kind") != KIND or value.get("version") != VERSION:
        raise OperatorDashboardInputManifestError("dashboard input manifest identity mismatch")
    allowed_top = {"schema", "kind", "version", "required", "optional", "single_content_operations"}
    unknown = set(value) - allowed_top
    if unknown:
        raise OperatorDashboardInputManifestError(f"unknown dashboard manifest top-level keys: {','.join(sorted(unknown))}")
    required = value.get("required")
    optional = value.get("optional", {})
    singles = value.get("single_content_operations", [])
    if not isinstance(required, dict) or set(required) != set(REQUIRED_KEYS):
        raise OperatorDashboardInputManifestError("dashboard manifest required receipt set mismatch")
    if not isinstance(optional, dict) or any(key not in OPTIONAL_KEYS for key in optional):
        raise OperatorDashboardInputManifestError("dashboard manifest optional receipt set contains unknown role")
    if not isinstance(singles, list) or len(singles) > 9:
        raise OperatorDashboardInputManifestError("dashboard manifest single-content operation list is invalid")
    return required, optional, singles


def render(manifest: dict[str, Any], receipt_root: Path) -> dict[str, Any]:
    required, optional, singles = _validate_manifest(manifest)
    root = _external_receipt_root(receipt_root)
    used: list[tuple[Path, str]] = []

    def load_role(raw: Any, role: str) -> dict[str, Any]:
        path = _resolve_relative_file(root, raw, role)
        for previous_path, previous_role in used:
            try:
                same = path.samefile(previous_path)
            except OSError as exc:
                raise OperatorDashboardInputManifestError(
                    f"unable to compare receipt file identity: {role}"
                ) from exc
            if same:
                raise OperatorDashboardInputManifestError(
                    f"one physical receipt file may not satisfy multiple dashboard roles: {previous_role},{role}"
                )
        used.append((path, role))
        return _read_json(path, f"dashboard receipt {role}")

    required_values = {key: load_role(required[key], key) for key in REQUIRED_KEYS}
    optional_values = {key: load_role(raw, key) for key, raw in optional.items()}
    single_values = [load_role(raw, f"single_content_operation[{index}]") for index, raw in enumerate(singles)]

    dashboard = _load_dashboard()
    try:
        value = dashboard.build(
            required_values["inventory_audit"],
            required_values["readiness_summary"],
            optional_values.get("readiness_verification"),
            optional_values.get("lock_verification"),
            optional_values.get("evidence_api_verification"),
            optional_values.get("content_closure"),
            optional_values.get("content_plan"),
            single_values,
            optional_values.get("public_auth_operation"),
            optional_values.get("content_closure_verification"),
            optional_values.get("evaluator_verification"),
            optional_values.get("final_attestation_operation"),
            optional_values.get("release_closure"),
            optional_values.get("authority_escrow_operation"),
            optional_values.get("immutable_release_verification"),
            optional_values.get("documentation_verification"),
            optional_values.get("cleanup_verification"),
            optional_values.get("final_repository_scan"),
            optional_values.get("final_release_verification"),
        )
    except Exception as exc:
        raise OperatorDashboardInputManifestError(f"repository-owned dashboard build failed: {exc}") from exc
    if not isinstance(value, dict) or value.get("kind") != "psmatrix.production-ga-operator-dashboard":
        raise OperatorDashboardInputManifestError("repository-owned dashboard returned invalid result")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the Production GA operator dashboard from a bounded external receipt-root manifest")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = _read_json(args.manifest, "dashboard input manifest")
        value = render(manifest, args.receipt_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_operator_dashboard_manifest=PASS stage={value['stage']}")
        print(f"ga_eligible={str(value['ga_eligible']).lower()}")
        print(f"release_closed={str(value['release_closed']).lower()}")
        return 0
    except (OSError, json.JSONDecodeError, OperatorDashboardInputManifestError, TypeError, ValueError, KeyError) as exc:
        print(f"Production GA dashboard manifest render failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
