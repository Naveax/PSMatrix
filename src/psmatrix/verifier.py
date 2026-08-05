from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import VerificationError
from .models import ExecutionResult, VerificationCheck
from .util import read_json, sha256_file


def contract_path_for(source: Path) -> Path:
    candidates = [
        source.with_name(source.name + ".psmatrix.json"),
        source.with_suffix(source.suffix + ".psmatrix.json"),
        source.with_name(source.stem + ".psmatrix.json"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def load_contract(source: Path) -> dict[str, Any]:
    path = contract_path_for(source)
    if not path.exists():
        return {"schema": 1, "expect": {"exit_code": 0}}
    value = read_json(path)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise VerificationError(f"Invalid verification contract: {path}")
    expect = value.get("expect")
    if not isinstance(expect, dict):
        raise VerificationError(f"Contract expect must be an object: {path}")
    return value


def _safe_workspace_path(workspace: Path, value: str) -> Path:
    target = (workspace / value).resolve()
    workspace = workspace.resolve()
    if target != workspace and workspace not in target.parents:
        raise VerificationError(f"Verification path escapes workspace: {value}")
    return target


def _lookup_json(value: Any, dotted_path: str) -> Any:
    current = value
    if dotted_path == "":
        return current
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise KeyError(dotted_path)
    return current


def _stream_payload(observation: dict[str, Any], name: str) -> dict[str, Any]:
    streams = observation.get("streams", {}) if isinstance(observation, dict) else {}
    value = streams.get(name, {}) if isinstance(streams, dict) else {}
    return value if isinstance(value, dict) else {}


def _record_text(record: Any) -> str:
    if isinstance(record, dict):
        return str(record.get("message", ""))
    return str(record)


def _stream_checks(expect: dict[str, Any], observation: dict[str, Any]) -> list[VerificationCheck]:
    checks: list[VerificationCheck] = []
    stream_expectations = expect.get("streams", {})
    if not isinstance(stream_expectations, dict):
        raise VerificationError("expect.streams must be an object")
    for stream_name, rule in stream_expectations.items():
        name = str(stream_name).lower()
        payload = _stream_payload(observation, name)
        actual_count = int(payload.get("count", 0) or 0)
        records = payload.get("records", [])
        if not isinstance(records, list):
            records = []
        if isinstance(rule, int):
            checks.append(VerificationCheck(
                kind="stream_count", passed=actual_count == rule,
                subject=f"stream.{name}", expected=rule, actual=actual_count,
            ))
            continue
        if not isinstance(rule, dict):
            raise VerificationError(f"Stream expectation for {name} must be an integer or object")
        if "count" in rule:
            expected_count = int(rule["count"])
            checks.append(VerificationCheck(
                kind="stream_count", passed=actual_count == expected_count,
                subject=f"stream.{name}", expected=expected_count, actual=actual_count,
            ))
        if "min_count" in rule:
            minimum = int(rule["min_count"])
            checks.append(VerificationCheck(
                kind="stream_min_count", passed=actual_count >= minimum,
                subject=f"stream.{name}", expected=f">={minimum}", actual=actual_count,
            ))
        if "max_count" in rule:
            maximum = int(rule["max_count"])
            checks.append(VerificationCheck(
                kind="stream_max_count", passed=actual_count <= maximum,
                subject=f"stream.{name}", expected=f"<={maximum}", actual=actual_count,
            ))
        corpus = "\n".join(_record_text(record) for record in records)
        for needle in rule.get("contains", []):
            checks.append(VerificationCheck(
                kind="stream_contains", passed=str(needle) in corpus,
                subject=f"stream.{name}", expected=str(needle), actual=corpus,
            ))
        for pattern in rule.get("regex", []):
            matched = re.search(str(pattern), corpus, flags=re.MULTILINE) is not None
            checks.append(VerificationCheck(
                kind="stream_regex", passed=matched,
                subject=f"stream.{name}", expected=str(pattern), actual=corpus,
            ))
    return checks


def _decode_case_output(case: dict[str, Any]) -> Any:
    raw = case.get("output_json")
    if not isinstance(raw, str):
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict):
        items = value.get("items")
        if isinstance(items, list):
            if len(items) == 1:
                return items[0]
            return items
    return value


def _module_checks(expect: dict[str, Any], observation: dict[str, Any]) -> list[VerificationCheck]:
    rule = expect.get("module")
    if rule is None:
        return []
    if not isinstance(rule, dict):
        raise VerificationError("expect.module must be an object")
    actual = observation.get("module") if isinstance(observation, dict) else None
    checks: list[VerificationCheck] = []
    checks.append(VerificationCheck(
        kind="module_present", passed=isinstance(actual, dict),
        subject="module", expected=True, actual=isinstance(actual, dict),
    ))
    if not isinstance(actual, dict):
        return checks
    for key in ("module_name", "version"):
        expected_key = "name" if key == "module_name" else key
        if expected_key in rule:
            checks.append(VerificationCheck(
                kind=f"module_{expected_key}",
                passed=str(actual.get(key)) == str(rule[expected_key]),
                subject=f"module.{expected_key}",
                expected=str(rule[expected_key]), actual=str(actual.get(key)),
            ))
    exported = sorted(str(item) for item in actual.get("exported_commands", []))
    if "exported_commands" in rule:
        expected_exported = sorted(str(item) for item in rule["exported_commands"])
        checks.append(VerificationCheck(
            kind="module_exports", passed=exported == expected_exported,
            subject="module.exported_commands", expected=expected_exported, actual=exported,
        ))
    for name in rule.get("exported_commands_contains", []):
        checks.append(VerificationCheck(
            kind="module_export_contains", passed=str(name) in exported,
            subject="module.exported_commands", expected=str(name), actual=exported,
        ))

    semantic = observation.get("semantic", {}) if isinstance(observation, dict) else {}
    cases = semantic.get("cases", []) if isinstance(semantic, dict) else []
    if not isinstance(cases, list):
        cases = []
    for index, expected_case in enumerate(rule.get("commands", []), start=1):
        if not isinstance(expected_case, dict):
            raise VerificationError("expect.module.commands entries must be objects")
        name = str(expected_case.get("name", ""))
        actual_case = next((item for item in cases if isinstance(item, dict) and int(item.get("index", -1)) == index), None)
        if actual_case is None:
            actual_case = next((item for item in cases if isinstance(item, dict) and str(item.get("name")) == name), None)
        checks.append(VerificationCheck(
            kind="module_command_executed", passed=isinstance(actual_case, dict),
            subject=f"module.command[{index}].{name}", expected=True, actual=isinstance(actual_case, dict),
        ))
        if not isinstance(actual_case, dict):
            continue
        case_expect = expected_case.get("expect", {})
        if not isinstance(case_expect, dict):
            raise VerificationError("module command expect must be an object")
        expected_status = str(case_expect.get("status", "completed"))
        checks.append(VerificationCheck(
            kind="module_command_status", passed=str(actual_case.get("status")) == expected_status,
            subject=f"module.command[{index}].status", expected=expected_status,
            actual=actual_case.get("status"),
        ))
        if "output_count" in case_expect:
            count = int(actual_case.get("output_count", 0) or 0)
            expected_count = int(case_expect["output_count"])
            checks.append(VerificationCheck(
                kind="module_command_output_count", passed=count == expected_count,
                subject=f"module.command[{index}].output_count", expected=expected_count, actual=count,
            ))
        if "output_equals" in case_expect:
            output = _decode_case_output(actual_case)
            checks.append(VerificationCheck(
                kind="module_command_output", passed=output == case_expect["output_equals"],
                subject=f"module.command[{index}].output", expected=case_expect["output_equals"], actual=output,
            ))
        if "native_exit_code" in case_expect:
            expected_native = int(case_expect["native_exit_code"])
            checks.append(VerificationCheck(
                kind="module_command_native_exit", passed=actual_case.get("last_exit_code") == expected_native,
                subject=f"module.command[{index}].native_exit_code", expected=expected_native,
                actual=actual_case.get("last_exit_code"),
            ))
    return checks


def _manifest_checks(expect: dict[str, Any], observation: dict[str, Any]) -> list[VerificationCheck]:
    rule = expect.get("manifest")
    if rule is None:
        return []
    if not isinstance(rule, dict):
        raise VerificationError("expect.manifest must be an object")
    actual = observation.get("manifest") if isinstance(observation, dict) else None
    checks: list[VerificationCheck] = [VerificationCheck(
        kind="manifest_present", passed=isinstance(actual, dict), subject="manifest",
        expected=True, actual=isinstance(actual, dict),
    )]
    if not isinstance(actual, dict):
        return checks
    for key in ("kind", "valid", "name", "version", "root_module"):
        if key in rule:
            checks.append(VerificationCheck(
                kind=f"manifest_{key}", passed=actual.get(key) == rule[key],
                subject=f"manifest.{key}", expected=rule[key], actual=actual.get(key),
            ))
    for key in ("exported_functions", "exported_cmdlets", "exported_aliases"):
        if key in rule:
            expected_values = sorted(str(item) for item in rule[key])
            actual_values = sorted(str(item) for item in actual.get(key, []))
            checks.append(VerificationCheck(
                kind=f"manifest_{key}", passed=actual_values == expected_values,
                subject=f"manifest.{key}", expected=expected_values, actual=actual_values,
            ))
    return checks


def verify(
    workspace: Path,
    execution: ExecutionResult,
    contract: dict[str, Any],
    observation: dict[str, Any] | None = None,
) -> list[VerificationCheck]:
    expect = contract["expect"]
    observation = observation or {}
    checks: list[VerificationCheck] = []

    if "exit_code" in expect:
        expected = int(expect["exit_code"])
        checks.append(VerificationCheck(
            kind="exit_code", passed=execution.exit_code == expected,
            subject="process", expected=expected, actual=execution.exit_code,
        ))

    if "native_exit_code" in expect:
        native = observation.get("native", {}) if isinstance(observation, dict) else {}
        actual_native = native.get("last_exit_code") if isinstance(native, dict) else None
        expected_native = int(expect["native_exit_code"])
        checks.append(VerificationCheck(
            kind="native_exit_code", passed=actual_native == expected_native,
            subject="powershell.LASTEXITCODE", expected=expected_native, actual=actual_native,
        ))

    if expect.get("stderr_empty") is True:
        actual = execution.stderr.strip()
        checks.append(VerificationCheck(
            kind="stderr_empty", passed=actual == "", subject="process.stderr",
            expected="", actual=actual,
        ))

    for needle in expect.get("stdout_contains", []):
        checks.append(VerificationCheck(
            kind="stdout_contains", passed=str(needle) in execution.stdout,
            subject="process.stdout", expected=str(needle), actual=execution.stdout,
        ))

    for pattern in expect.get("stdout_regex", []):
        matched = re.search(str(pattern), execution.stdout, flags=re.MULTILINE) is not None
        checks.append(VerificationCheck(
            kind="stdout_regex", passed=matched, subject="process.stdout",
            expected=str(pattern), actual=execution.stdout,
        ))

    for file_expectation in expect.get("files", []):
        relative = str(file_expectation["path"])
        path = _safe_workspace_path(workspace, relative)
        exists = path.exists()
        expected_exists = bool(file_expectation.get("exists", True))
        checks.append(VerificationCheck(
            kind="file_exists", passed=exists == expected_exists, subject=relative,
            expected=expected_exists, actual=exists,
        ))
        if exists and file_expectation.get("valid_json") is True:
            try:
                read_json(path)
                passed, message = True, None
            except (OSError, ValueError) as exc:
                passed, message = False, str(exc)
            checks.append(VerificationCheck(
                kind="valid_json", passed=passed, subject=relative,
                expected=True, actual=passed, message=message,
            ))
        if exists and "sha256" in file_expectation:
            actual_hash = sha256_file(path)
            expected_hash = str(file_expectation["sha256"]).lower()
            checks.append(VerificationCheck(
                kind="file_sha256", passed=actual_hash == expected_hash, subject=relative,
                expected=expected_hash, actual=actual_hash,
            ))

    for json_expectation in expect.get("json", []):
        relative = str(json_expectation["path"])
        path = _safe_workspace_path(workspace, relative)
        try:
            value = read_json(path)
            actual = _lookup_json(value, str(json_expectation.get("property", "")))
            expected = json_expectation.get("equals")
            passed, message = actual == expected, None
        except (OSError, ValueError, KeyError) as exc:
            actual = None
            expected = json_expectation.get("equals")
            passed, message = False, str(exc)
        checks.append(VerificationCheck(
            kind="json_equals", passed=passed,
            subject=f"{relative}:{json_expectation.get('property', '')}",
            expected=expected, actual=actual, message=message,
        ))

    checks.extend(_stream_checks(expect, observation))
    checks.extend(_module_checks(expect, observation))
    checks.extend(_manifest_checks(expect, observation))
    return checks
