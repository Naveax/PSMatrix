from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .diagnostics import report_diagnostics
from .errors import PSMatrixError
from .util import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso

_REPAIR_SCHEMA = 1
_MAX_PATCH_FILES = 32
_MAX_EDIT_BYTES = 2 * 1024 * 1024


class RepairError(PSMatrixError):
    """Raised when a repair transaction or patch proposal is unsafe."""


@dataclass(frozen=True)
class AppliedFile:
    path: str
    before_sha256: str
    after_sha256: str
    diff: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def validation_argv_sha256(argv: list[str]) -> str:
    return hashlib.sha256(_canonical_bytes(argv)).hexdigest()


def redact_validation_argv(argv: list[str]) -> list[str]:
    sensitive = {"--arg", "--param", "--param-json", "--env", "--stdin-text"}
    result: list[str] = []
    mask_next = False
    for value in argv:
        if mask_next:
            result.append("<redacted>")
            mask_next = False
            continue
        result.append(value)
        if value in sensitive:
            mask_next = True
    return result


def _inside(root: Path, path: Path) -> bool:
    try:
        return os.path.commonpath([str(root), str(path)]) == str(root)
    except ValueError:
        return False


def resolve_project_file(root: Path, value: str, *, must_exist: bool = True) -> Path:
    root = root.resolve()
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=must_exist)
    else:
        resolved = (root / candidate).resolve(strict=must_exist)
    if not _inside(root, resolved):
        raise RepairError(f"Path escapes repair root: {value}")
    relative = resolved.relative_to(root)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RepairError(f"Symlink paths are not allowed in repair transactions: {value}")
    if must_exist and not resolved.is_file():
        raise RepairError(f"Repair source is not a regular file: {resolved}")
    return resolved


def build_repair_plan(report: dict[str, Any], root: Path, *, validation_argv: list[str] | None = None) -> dict[str, Any]:
    root = root.resolve()
    diagnostics, summary = report_diagnostics(report)
    sources: dict[str, dict[str, Any]] = {}
    for diagnostic in diagnostics:
        source_value = str(diagnostic.get("source") or "")
        if not source_value:
            continue
        try:
            source = resolve_project_file(root, source_value)
        except RepairError:
            continue
        relative = source.relative_to(root).as_posix()
        item = sources.setdefault(relative, {
            "path": relative,
            "sha256": sha256_file(source),
            "size": source.stat().st_size,
            "diagnostic_codes": [],
            "diagnostics": [],
        })
        code = str(diagnostic.get("code") or "UNKNOWN")
        if code not in item["diagnostic_codes"]:
            item["diagnostic_codes"].append(code)
        item["diagnostics"].append(diagnostic)
    for item in sources.values():
        item["diagnostic_codes"].sort()
        item["diagnostics"].sort(key=lambda value: (
            int(value.get("line") or 0), int(value.get("column") or 0), str(value.get("code")),
        ))
    report_sha256 = _canonical_sha256(report)
    validation = validation_argv or []
    baseline_targets = []
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        source_value = str(target.get("source") or "")
        if not source_value:
            continue
        try:
            source = resolve_project_file(root, source_value)
        except RepairError:
            continue
        baseline_targets.append({
            "path": source.relative_to(root).as_posix(),
            "runtime_id": str(target.get("runtime_id") or ""),
            "runtime_version": str(target.get("runtime_version") or ""),
            "status": str(target.get("status") or ""),
        })
    baseline_targets.sort(key=lambda value: (value["path"], value["runtime_id"]))
    material = {
        "schema": _REPAIR_SCHEMA,
        "report_sha256": report_sha256,
        "root": str(root),
        "sources": [sources[key] for key in sorted(sources)],
        "baseline_targets": baseline_targets,
        "validation_argv_sha256": validation_argv_sha256(validation),
        "validation_argv_redacted": redact_validation_argv(validation),
        "diagnostic_summary": summary,
    }
    plan_id = "rpl_" + hashlib.sha256(_canonical_bytes(material)).hexdigest()[:24]
    return {
        "schema": _REPAIR_SCHEMA,
        "kind": "psmatrix.repair-plan",
        "plan_id": plan_id,
        "created_at": utc_now_iso(),
        **material,
        "constraints": {
            "existing_files_only": True,
            "symlinks_allowed": False,
            "maximum_files": _MAX_PATCH_FILES,
            "maximum_edit_bytes": _MAX_EDIT_BYTES,
            "required_validation_status": "PASS",
            "rollback_on_failure": True,
        },
    }


def _replace_occurrence(text: str, old: str, new: str, occurrence: int | None) -> tuple[str, int]:
    if not old:
        raise RepairError("Patch edit 'old' value cannot be empty")
    count = text.count(old)
    if count == 0:
        raise RepairError("Expected patch text was not found")
    if occurrence is None:
        if count != 1:
            raise RepairError(f"Patch text is ambiguous: found {count} occurrences")
        occurrence = 1
    if occurrence < 1 or occurrence > count:
        raise RepairError(f"Patch occurrence {occurrence} is outside 1..{count}")
    start = -1
    search_from = 0
    for _ in range(occurrence):
        start = text.find(old, search_from)
        search_from = start + len(old)
    return text[:start] + new + text[start + len(old):], occurrence


def propose_patch(root: Path, proposal: dict[str, Any], *, plan: dict[str, Any] | None = None) -> dict[str, Any]:
    root = root.resolve()
    files = proposal.get("files")
    if not isinstance(files, list) or not files:
        raise RepairError("Patch proposal requires a non-empty files array")
    if len(files) > _MAX_PATCH_FILES:
        raise RepairError(f"Patch proposal exceeds {_MAX_PATCH_FILES} files")
    plan_sources = {
        str(item.get("path")): item for item in (plan or {}).get("sources", []) if isinstance(item, dict)
    }
    actions: list[dict[str, Any]] = []
    total_bytes = 0
    for raw in files:
        if not isinstance(raw, dict):
            raise RepairError("Patch file entries must be objects")
        path_value = str(raw.get("path") or "")
        source = resolve_project_file(root, path_value)
        relative = source.relative_to(root).as_posix()
        before_bytes = source.read_bytes()
        try:
            text = before_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepairError(f"Only UTF-8 source repair is supported: {relative}") from exc
        before_sha256 = hashlib.sha256(before_bytes).hexdigest()
        expected = raw.get("before_sha256")
        if expected is None and relative in plan_sources:
            expected = plan_sources[relative].get("sha256")
        if expected is not None and not hmac.compare_digest(str(expected).lower(), before_sha256):
            raise RepairError(f"Source changed since diagnosis: {relative}")
        edits = raw.get("edits")
        if not isinstance(edits, list) or not edits:
            raise RepairError(f"Patch file {relative} requires non-empty edits")
        applied_edits: list[dict[str, Any]] = []
        updated = text
        for edit in edits:
            if not isinstance(edit, dict):
                raise RepairError(f"Patch edits for {relative} must be objects")
            old = edit.get("old")
            new = edit.get("new")
            if not isinstance(old, str) or not isinstance(new, str):
                raise RepairError("Patch edit old/new values must be strings")
            total_bytes += len(old.encode("utf-8")) + len(new.encode("utf-8"))
            if total_bytes > _MAX_EDIT_BYTES:
                raise RepairError("Patch proposal exceeds maximum edit bytes")
            occurrence_value = edit.get("occurrence")
            occurrence = int(occurrence_value) if occurrence_value is not None else None
            updated, resolved_occurrence = _replace_occurrence(updated, old, new, occurrence)
            supplied_codes = {str(value) for value in edit.get("diagnostic_codes", []) if str(value)}
            if plan is not None:
                allowed_codes = {
                    str(value) for value in plan_sources.get(relative, {}).get("diagnostic_codes", [])
                    if str(value)
                }
                if supplied_codes - allowed_codes:
                    unknown = ", ".join(sorted(supplied_codes - allowed_codes))
                    raise RepairError(
                        f"Patch edit for {relative} references diagnostics outside the repair plan: {unknown}"
                    )
                if not supplied_codes:
                    supplied_codes = allowed_codes
            applied_edits.append({
                "old": old,
                "new": new,
                "occurrence": resolved_occurrence,
                "diagnostic_codes": sorted(supplied_codes),
                "reason": str(edit.get("reason") or ""),
            })
        if updated == text:
            raise RepairError(f"Patch proposal does not change {relative}")
        after_bytes = updated.encode("utf-8")
        after_sha256 = hashlib.sha256(after_bytes).hexdigest()
        diff = "".join(difflib.unified_diff(
            text.splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=f"a/{relative}", tofile=f"b/{relative}", n=3,
        ))
        actions.append({
            "path": relative,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "mode": source.stat().st_mode & 0o7777,
            "edits": applied_edits,
            "unified_diff": diff,
        })
    material = {
        "schema": _REPAIR_SCHEMA,
        "plan_id": (plan or {}).get("plan_id"),
        "report_sha256": (plan or {}).get("report_sha256"),
        "validation_argv_sha256": (plan or {}).get("validation_argv_sha256"),
        "baseline_targets": (plan or {}).get("baseline_targets", []),
        "actions": actions,
    }
    bundle_id = "rpb_" + hashlib.sha256(_canonical_bytes(material)).hexdigest()[:24]
    return {
        "schema": _REPAIR_SCHEMA,
        "kind": "psmatrix.patch-bundle",
        "bundle_id": bundle_id,
        "created_at": utc_now_iso(),
        **material,
        "summary": {
            "files": len(actions),
            "edit_bytes": total_bytes,
            "diagnostic_codes": sorted({
                code for action in actions for edit in action["edits"] for code in edit["diagnostic_codes"]
            }),
        },
    }


def _replay_action(root: Path, action: dict[str, Any]) -> tuple[Path, bytes, bytes, int]:
    source = resolve_project_file(root, str(action.get("path") or ""))
    before = source.read_bytes()
    before_sha256 = hashlib.sha256(before).hexdigest()
    if not hmac.compare_digest(before_sha256, str(action.get("before_sha256") or "")):
        raise RepairError(f"Source hash mismatch before patch: {action.get('path')}")
    try:
        updated = before.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepairError(f"Only UTF-8 source repair is supported: {action.get('path')}") from exc
    edits = action.get("edits")
    if not isinstance(edits, list) or not edits:
        raise RepairError("Patch action has no edits")
    for edit in edits:
        updated, _ = _replace_occurrence(
            updated, str(edit.get("old") or ""), str(edit.get("new") or ""), int(edit.get("occurrence") or 1),
        )
    after = updated.encode("utf-8")
    after_sha256 = hashlib.sha256(after).hexdigest()
    if not hmac.compare_digest(after_sha256, str(action.get("after_sha256") or "")):
        raise RepairError(f"Patch replay hash mismatch: {action.get('path')}")
    return source, before, after, source.stat().st_mode & 0o7777


def apply_bundle(root: Path, bundle: dict[str, Any], transaction_root: Path) -> tuple[str, list[AppliedFile], Path]:
    root = root.resolve()
    if bundle.get("schema") != _REPAIR_SCHEMA or bundle.get("kind") != "psmatrix.patch-bundle":
        raise RepairError("Unsupported patch bundle schema")
    actions = bundle.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > _MAX_PATCH_FILES:
        raise RepairError("Patch bundle action count is invalid")
    transaction_id = "rtx_" + uuid.uuid4().hex
    transaction = transaction_root.resolve() / transaction_id
    backup_root = transaction / "backups"
    backup_root.mkdir(parents=True, mode=0o700)
    os.chmod(transaction, 0o700)
    os.chmod(backup_root, 0o700)
    prepared: list[tuple[Path, bytes, bytes, int, Path]] = []
    applied: list[AppliedFile] = []
    seen_paths: set[str] = set()
    try:
        for action in actions:
            if not isinstance(action, dict):
                raise RepairError("Patch actions must be objects")
            source, before, after, mode = _replay_action(root, action)
            relative = source.relative_to(root)
            relative_key = relative.as_posix().casefold()
            if relative_key in seen_paths:
                raise RepairError(f"Duplicate patch action for source: {relative.as_posix()}")
            seen_paths.add(relative_key)
            backup = backup_root / relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(backup, before)
            os.chmod(backup, mode)
            prepared.append((source, before, after, mode, backup))
        for source, before, after, mode, _backup in prepared:
            atomic_write_bytes(source, after)
            os.chmod(source, mode)
            relative = source.relative_to(root).as_posix()
            diff = "".join(difflib.unified_diff(
                before.decode("utf-8").splitlines(keepends=True),
                after.decode("utf-8").splitlines(keepends=True),
                fromfile=f"a/{relative}", tofile=f"b/{relative}", n=3,
            ))
            applied.append(AppliedFile(
                path=relative,
                before_sha256=hashlib.sha256(before).hexdigest(),
                after_sha256=hashlib.sha256(after).hexdigest(),
                diff=diff,
            ))
        atomic_write_json(transaction / "transaction.json", {
            "schema": _REPAIR_SCHEMA,
            "transaction_id": transaction_id,
            "root": str(root),
            "bundle_id": bundle.get("bundle_id"),
            "created_at": utc_now_iso(),
            "status": "applied",
            "files": [item.__dict__ for item in applied],
        })
        return transaction_id, applied, transaction
    except BaseException:
        for source, before, _after, mode, _backup in reversed(prepared):
            try:
                atomic_write_bytes(source, before)
                os.chmod(source, mode)
            except OSError:
                pass
        shutil.rmtree(transaction, ignore_errors=True)
        raise


def rollback_transaction(root: Path, transaction: Path) -> list[str]:
    root = root.resolve()
    payload = read_json(transaction / "transaction.json")
    restored: list[str] = []
    for value in payload.get("files", []):
        relative = str(value.get("path") or "")
        destination = resolve_project_file(root, relative)
        backup = transaction / "backups" / relative
        if not backup.is_file():
            raise RepairError(f"Repair backup missing: {relative}")
        atomic_write_bytes(destination, backup.read_bytes())
        restored.append(relative)
    payload["status"] = "rolled_back"
    payload["rolled_back_at"] = utc_now_iso()
    atomic_write_json(transaction / "transaction.json", payload)
    return restored


def _validate_test_argv(root: Path, argv: list[str], home: Path) -> list[str]:
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv or argv[0] != "test":
        raise RepairError("Repair validation arguments must begin with 'test'")
    from .cli import build_parser
    parsed = build_parser().parse_args(["--home", str(home), *argv])
    if parsed.command != "test":
        raise RepairError("Repair validation may only call the test command")
    if parsed.install_missing:
        raise RepairError("Repair validation cannot install runtimes")
    if parsed.network != "none" or parsed.sandbox == "direct":
        raise RepairError("Repair validation requires network=none and a non-direct sandbox")
    for path in parsed.paths:
        resolve_project_file(root, str(path))
    forbidden_outputs = [
        parsed.report_json, parsed.report_junit, parsed.report_sarif, parsed.report_html,
        parsed.report_sbom, parsed.evidence_bundle,
    ]
    if any(value is not None for value in forbidden_outputs):
        raise RepairError("Repair validation report outputs are managed by the repair engine")
    return argv


def run_validation(root: Path, home: Path, argv: list[str], report_path: Path) -> tuple[int, dict[str, Any], str, str]:
    argv = _validate_test_argv(root, argv, home)
    command = [sys.executable, "-m", "psmatrix", "--home", str(home), *argv, "--report-json", str(report_path), "--json"]
    package_src = str(Path(__file__).resolve().parents[1])
    inherited_pythonpath = os.environ.get("PYTHONPATH")
    pythonpath = package_src if not inherited_pythonpath else package_src + os.pathsep + inherited_pythonpath
    process = subprocess.run(
        command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", timeout=3600,
        env={**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONPATH": pythonpath},
    )
    if not report_path.is_file():
        raise RepairError(
            f"Validation did not produce a report (exit {process.returncode}): {process.stderr[-4096:]}"
        )
    report = read_json(report_path)
    if not isinstance(report, dict):
        raise RepairError("Validation report root must be an object")
    return process.returncode, report, process.stdout, process.stderr


def _session_payload(path: Path, *, max_attempts: int) -> dict[str, Any]:
    if path.is_file():
        payload = read_json(path)
        if payload.get("schema") != _REPAIR_SCHEMA:
            raise RepairError("Unsupported repair session schema")
        return payload
    return {
        "schema": _REPAIR_SCHEMA,
        "kind": "psmatrix.repair-session",
        "session_id": "rrs_" + uuid.uuid4().hex,
        "created_at": utc_now_iso(),
        "max_attempts": max_attempts,
        "attempts": [],
        "status": "active",
    }


def _validation_covers_baseline(report: dict[str, Any], baseline_targets: list[dict[str, Any]], root: Path) -> tuple[bool, list[dict[str, str]]]:
    expected = {
        (str(item.get("path") or ""), str(item.get("runtime_id") or ""))
        for item in baseline_targets if isinstance(item, dict)
    }
    if not expected:
        return True, []
    actual: set[tuple[str, str]] = set()
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        try:
            source = resolve_project_file(root, str(target.get("source") or ""))
        except RepairError:
            continue
        actual.add((source.relative_to(root).as_posix(), str(target.get("runtime_id") or "")))
    missing = sorted(expected - actual)
    return not missing, [{"path": path, "runtime_id": runtime_id} for path, runtime_id in missing]


def apply_and_validate(
    root: Path,
    home: Path,
    bundle: dict[str, Any],
    validation_argv: list[str],
    *,
    session_path: Path,
    max_attempts: int = 3,
    accept_statuses: Iterable[str] = ("PASS",),
) -> dict[str, Any]:
    root = root.resolve()
    home = home.resolve()
    session_path = session_path.resolve()
    if not bundle.get("plan_id") or not bundle.get("report_sha256"):
        raise RepairError("Validated repair requires a diagnosis-bound patch bundle")
    expected_validation_hash = bundle.get("validation_argv_sha256")
    if not expected_validation_hash:
        raise RepairError("Patch bundle is missing the validation argument digest")
    actual_validation_hash = validation_argv_sha256(validation_argv)
    if not hmac.compare_digest(str(expected_validation_hash), actual_validation_hash):
        raise RepairError("Validation arguments do not match the diagnosed repair plan")
    transaction_root = home / "repair-transactions"
    transaction_root.mkdir(parents=True, exist_ok=True)
    os.chmod(transaction_root, 0o700)
    lock_path = session_path.with_suffix(session_path.suffix + ".lock")
    with exclusive_lock(lock_path):
        session = _session_payload(session_path, max_attempts=max_attempts)
        attempts = session.setdefault("attempts", [])
        if len(attempts) >= int(session.get("max_attempts", max_attempts)):
            raise RepairError("Maximum repair attempts reached")
        attempt_number = len(attempts) + 1
        transaction_id, files, transaction = apply_bundle(root, bundle, transaction_root)
        report_path = transaction / "validation-report.json"
        accepted = False
        validation_error: str | None = None
        report: dict[str, Any] = {}
        stdout = ""
        stderr = ""
        try:
            exit_code, report, stdout, stderr = run_validation(root, home, validation_argv, report_path)
            coverage_ok, missing_targets = _validation_covers_baseline(
                report, bundle.get("baseline_targets", []), root
            )
            accepted = exit_code == 0 and str(report.get("status")) in set(accept_statuses) and coverage_ok
            if not coverage_ok:
                validation_error = "Validation report omitted baseline targets: " + json.dumps(missing_targets, sort_keys=True)
        except BaseException as exc:
            exit_code = 2
            validation_error = f"{type(exc).__name__}: {exc}"
        rolled_back: list[str] = []
        if not accepted:
            rolled_back = rollback_transaction(root, transaction)
        diagnostics, summary = report_diagnostics(report) if report else ([], {"count": 0})
        attempt = {
            "attempt": attempt_number,
            "started_at": utc_now_iso(),
            "bundle_id": bundle.get("bundle_id"),
            "transaction_id": transaction_id,
            "files": [item.__dict__ for item in files],
            "validation_argv": redact_validation_argv(validation_argv),
            "validation_argv_sha256": actual_validation_hash,
            "validation_exit_code": exit_code,
            "validation_status": report.get("status") if report else None,
            "validation_report_sha256": _canonical_sha256(report) if report else None,
            "diagnostic_summary": summary,
            "accepted": accepted,
            "rolled_back": rolled_back,
            "error": validation_error,
            "stdout": {"bytes": len(stdout.encode("utf-8")), "sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest()},
            "stderr": {"bytes": len(stderr.encode("utf-8")), "sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest()},
        }
        attempts.append(attempt)
        session["updated_at"] = utc_now_iso()
        session["status"] = "accepted" if accepted else "active"
        atomic_write_json(session_path, session)
        return {
            "schema": _REPAIR_SCHEMA,
            "session_id": session["session_id"],
            "attempt": attempt,
            "report": report,
            "accepted": accepted,
            "transaction_path": str(transaction),
        }
