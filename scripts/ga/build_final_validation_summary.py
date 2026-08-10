from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.release import verify_release_manifest
from psmatrix.util import atomic_write_json, read_json, sha256_file, utc_now_iso


_VERSION = "2.0.0"
_FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
_RELEASE_ARTIFACTS = {
    "psmatrix-2.0.0-py3-none-any.whl",
    "psmatrix-2.0.0-source.tar.gz",
    "psmatrix-2.0.0-source.zip",
    "psmatrix-2.0.0-windows-certification-kit.zip",
    "psmatrix-2.0.0-windows-provisioning-kit.zip",
    "psmatrix-2.0.0-windows-workers.zip",
}
_DEFERRED_MODULES = ("test_integration.py",)
_OCI_TARGET = "tests.test_oci.OciRuntimeTests.test_image_reference_validation"
_CHILD_CODE = r'''
import io
import json
import sys
import unittest

target = sys.argv[1]
suite = unittest.defaultTestLoader.loadTestsFromName(target)
count = suite.countTestCases()
if count <= 0:
    print(json.dumps({"target": target, "tests": 0, "failures": 1, "errors": 0, "skipped": 0, "unexpected_successes": 0, "successful": False, "transcript": "no tests loaded"}, sort_keys=True))
    raise SystemExit(0)
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2, failfast=False).run(suite)
payload = {
    "target": target,
    "tests": int(result.testsRun),
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skipped": len(result.skipped),
    "unexpected_successes": len(result.unexpectedSuccesses),
    "successful": bool(result.wasSuccessful()),
    "transcript": stream.getvalue()[-32768:],
}
print(json.dumps(payload, sort_keys=True))
'''


class FinalValidationError(RuntimeError):
    pass


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _json(path: Path) -> dict[str, Any]:
    try:
        value = read_json(path.resolve())
    except Exception as exc:
        raise FinalValidationError(f"Could not read JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise FinalValidationError(f"JSON root must be an object: {path}")
    return value


def _git(source: Path, *args: str) -> str:
    result = _run(["git", "-C", str(source.resolve()), *args], cwd=ROOT)
    if result.returncode != 0:
        raise FinalValidationError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _require_final_source(source_root: Path) -> Path:
    source = source_root.resolve()
    if not source.is_dir():
        raise FinalValidationError(f"Final source root is missing: {source}")
    head = _git(source, "rev-parse", "HEAD").lower()
    if head != _FINAL_COMMIT:
        raise FinalValidationError(f"Final source HEAD mismatch: {head} != {_FINAL_COMMIT}")
    if _git(source, "status", "--porcelain"):
        raise FinalValidationError("Final source checkout is dirty")
    value = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
    if str((value.get("project") or {}).get("version") or "") != _VERSION:
        raise FinalValidationError("Final source pyproject version is not exact 2.0.0")
    return source


def _test_targets(repo_root: Path) -> tuple[list[str], list[str]]:
    tests = repo_root / "tests"
    if not tests.is_dir():
        raise FinalValidationError("tests directory is missing")
    targets: list[str] = []
    deferred: list[str] = []
    for path in sorted(tests.glob("test_*.py"), key=lambda item: item.name.casefold()):
        if path.name in _DEFERRED_MODULES:
            deferred.append(path.name)
            continue
        if path.name == "test_oci.py":
            targets.append(_OCI_TARGET)
            continue
        targets.append(f"tests.{path.stem}")
    if not targets:
        raise FinalValidationError("Final validation suite is empty")
    return targets, deferred


def run_suite(repo_root: Path, output: Path) -> dict[str, Any]:
    repo = _require_final_source(repo_root)
    targets, deferred = _test_targets(repo)
    rows: list[dict[str, Any]] = []
    total = failures = errors = skipped = unexpected = 0
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo / "src") + os.pathsep + str(repo)
    for target in targets:
        completed = _run([sys.executable, "-c", _CHILD_CODE, target], cwd=repo, env=env)
        if completed.returncode != 0:
            raise FinalValidationError(
                f"Validation child process failed before producing a result: {target}; "
                f"exit={completed.returncode}; stderr={completed.stderr[-8192:]}"
            )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if not lines:
            raise FinalValidationError(f"Validation child produced no result: {target}")
        try:
            row = json.loads(lines[-1])
        except json.JSONDecodeError as exc:
            raise FinalValidationError(f"Validation child result is not JSON: {target}") from exc
        if not isinstance(row, dict) or row.get("target") != target:
            raise FinalValidationError(f"Validation child identity mismatch: {target}")
        rows.append(row)
        total += int(row.get("tests") or 0)
        failures += int(row.get("failures") or 0)
        errors += int(row.get("errors") or 0)
        skipped += int(row.get("skipped") or 0)
        unexpected += int(row.get("unexpected_successes") or 0)
        if row.get("successful") is not True or any(int(row.get(name) or 0) for name in ("failures", "errors", "skipped", "unexpected_successes")):
            raise FinalValidationError(
                f"Final validation target is not clean PASS: {target}; "
                f"failures={row.get('failures')} errors={row.get('errors')} "
                f"skipped={row.get('skipped')} unexpected_successes={row.get('unexpected_successes')}"
            )
    passed = total - failures - errors - skipped - unexpected
    if total <= 0 or passed != total:
        raise FinalValidationError("Final validation test accounting is incomplete")
    report = {
        "schema": 1,
        "kind": "psmatrix.final-validation-suite",
        "status": "PASS",
        "source_commit": _FINAL_COMMIT,
        "source_root": str(repo),
        "executed_modules": targets,
        "deferred_modules": deferred,
        "automated_tests": {
            "passed": passed,
            "failed": failures + errors + unexpected,
            "skipped": skipped,
            "total": total,
        },
        "module_results": rows,
    }
    atomic_write_json(output.resolve(), report)
    return report


def _reproducible(value: Any, label: str) -> bool:
    if not isinstance(value, dict) or value.get("reproducible") is not True:
        raise FinalValidationError(f"Final rebuilt artifact is not reproducible: {label}")
    return True


def _verify_rebuilt_release(rebuilt_root: Path, signed_root: Path) -> dict[str, bool]:
    rebuilt = rebuilt_root.resolve()
    report_path = rebuilt / "psmatrix-2.0.0-windows-authority-final-staging.json"
    report = _json(report_path)
    if report.get("status") != "READY_FOR_FINAL_RELEASE_LOCK_REVIEW" or report.get("version") != _VERSION or report.get("release_commit") != _FINAL_COMMIT:
        raise FinalValidationError("Deterministic final rebuild report identity mismatch")
    if report.get("private_key_read") is not False or report.get("release_artifacts_signed") is not False:
        raise FinalValidationError("Deterministic final rebuild crossed the signing boundary")
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 6:
        raise FinalValidationError("Deterministic final rebuild must contain exactly six artifacts")
    by_name = {str(item.get("name") or ""): item for item in artifacts if isinstance(item, dict)}
    if set(by_name) != _RELEASE_ARTIFACTS:
        raise FinalValidationError("Deterministic final rebuild artifact set is not exact")
    for name in sorted(_RELEASE_ARTIFACTS):
        rebuilt_path = rebuilt / name
        signed_path = signed_root / name
        if not rebuilt_path.is_file() or not signed_path.is_file():
            raise FinalValidationError(f"Final release artifact is missing during reproducibility validation: {name}")
        item = by_name[name]
        rebuilt_sha = sha256_file(rebuilt_path)
        signed_sha = sha256_file(signed_path)
        if rebuilt_sha != item.get("sha256") or rebuilt_path.stat().st_size != int(item.get("size") or -1):
            raise FinalValidationError(f"Rebuild report does not match rebuilt bytes: {name}")
        if rebuilt_sha != signed_sha or rebuilt_path.stat().st_size != signed_path.stat().st_size:
            raise FinalValidationError(f"Signed final artifact differs from deterministic rebuild: {name}")
    reproducibility = report.get("reproducibility") if isinstance(report.get("reproducibility"), dict) else {}
    return {
        "source_zip": _reproducible(reproducibility.get("source_zip"), "source_zip"),
        "source_tar_gz": _reproducible(reproducibility.get("source_tar_gz"), "source_tar_gz"),
        "wheel": _reproducible(reproducibility.get("wheel"), "wheel"),
    }


def _offline_install(wheel: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="psmatrix-final-offline-install-") as temp:
        venv = Path(temp) / "venv"
        create = _run([sys.executable, "-m", "venv", str(venv)], cwd=ROOT)
        if create.returncode != 0:
            raise FinalValidationError(f"Offline validation venv creation failed: {create.stderr[-8192:]}")
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.is_file():
            raise FinalValidationError("Offline validation venv Python is missing")
        env = os.environ.copy()
        env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
        install = _run(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", "--disable-pip-version-check", str(wheel.resolve())],
            cwd=ROOT,
            env=env,
        )
        if install.returncode != 0:
            raise FinalValidationError(
                f"Offline wheel install failed: exit={install.returncode}; stdout={install.stdout[-8192:]}; stderr={install.stderr[-8192:]}"
            )
        probe = _run(
            [str(python), "-c", "import psmatrix; assert psmatrix.__version__ == '2.0.0'; print(psmatrix.__version__)"],
            cwd=ROOT,
            env=env,
        )
        if probe.returncode != 0 or probe.stdout.strip() != _VERSION:
            raise FinalValidationError(f"Offline installed package identity check failed: {probe.stdout!r} / {probe.stderr!r}")
        return {"exit_code": 0, "version": probe.stdout.strip(), "network_index_disabled": True}


def build_summary(*, source_root: Path, signed_root: Path, rebuilt_root: Path, test_report: Path, output: Path) -> dict[str, Any]:
    source = _require_final_source(source_root)
    signed = signed_root.resolve()
    if not signed.is_dir():
        raise FinalValidationError("Signed final release root is missing")
    manifest = signed / "psmatrix-2.0.0-release.json"
    public_key = signed / "psmatrix-2.0.0-release-public.pem"
    signing_status_path = signed / "psmatrix-2.0.0-protected-release-signing-status.json"
    for path in (manifest, public_key, signing_status_path):
        if not path.is_file() or path.is_symlink():
            raise FinalValidationError(f"Signed final release file is missing or unsafe: {path.name}")
    verification = verify_release_manifest(manifest, signed, signing_public_key=public_key)
    if verification.get("valid") is not True or verification.get("version") != _VERSION:
        raise FinalValidationError("Signed final 2.0.0 release verification did not PASS")
    if set(verification.get("artifacts") or []) != _RELEASE_ARTIFACTS:
        raise FinalValidationError("Signed final release artifact inventory is not exact")
    signing_status = _json(signing_status_path)
    required_status = {
        "status": "PASS",
        "version": _VERSION,
        "release_commit": _FINAL_COMMIT,
        "release_artifacts_signed": True,
        "signed_release_manifest_verified": True,
        "private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    for field, expected in required_status.items():
        if signing_status.get(field) != expected:
            raise FinalValidationError(f"Signed final release status boundary mismatch: {field}")

    tests = _json(test_report)
    if tests.get("status") != "PASS" or tests.get("source_commit") != _FINAL_COMMIT:
        raise FinalValidationError("Final validation test suite status/source binding mismatch")
    accounting = tests.get("automated_tests") if isinstance(tests.get("automated_tests"), dict) else {}
    passed = int(accounting.get("passed") or 0)
    failed = int(accounting.get("failed") or 0)
    skipped = int(accounting.get("skipped") or 0)
    total = int(accounting.get("total") or 0)
    if passed <= 0 or passed != total or failed or skipped:
        raise FinalValidationError("Final validation test accounting is not complete clean PASS")

    reproducibility = _verify_rebuilt_release(rebuilt_root, signed)
    offline = _offline_install(signed / "psmatrix-2.0.0-py3-none-any.whl")
    summary = {
        "schema": 1,
        "kind": "psmatrix.validation-summary",
        "version": _VERSION,
        "status": "PASS",
        "git_commit": _FINAL_COMMIT,
        "validated_at": utc_now_iso(),
        "automated_tests": {"passed": passed, "failed": 0, "skipped": 0, "total": total},
        "reproducibility": reproducibility,
        "offline_install_exit_code": int(offline["exit_code"]),
        "core_release_signature_valid": True,
        "distribution_signature_valid": True,
        "audit": {
            "source_head": _git(source, "rev-parse", "HEAD").lower(),
            "release_manifest_sha256": sha256_file(manifest),
            "release_public_key_sha256": sha256_file(public_key),
            "protected_signing_status_sha256": sha256_file(signing_status_path),
            "test_report_sha256": sha256_file(test_report.resolve()),
            "rebuilt_staging_report_sha256": sha256_file(rebuilt_root.resolve() / "psmatrix-2.0.0-windows-authority-final-staging.json"),
            "offline_install": offline,
            "deferred_modules": list(tests.get("deferred_modules") or []),
            "network_downloads_used_for_rebuild": False,
        },
    }
    atomic_write_json(output.resolve(), summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the exact PSMatrix 2.0.0 final validation summary")
    sub = parser.add_subparsers(dest="command", required=True)
    suite = sub.add_parser("test-suite")
    suite.add_argument("--repo-root", type=Path, required=True)
    suite.add_argument("--output", type=Path, required=True)
    build = sub.add_parser("build-summary")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--signed-root", type=Path, required=True)
    build.add_argument("--rebuilt-root", type=Path, required=True)
    build.add_argument("--test-report", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "test-suite":
        print(json.dumps(run_suite(args.repo_root, args.output), indent=2, sort_keys=True))
        return 0
    result = build_summary(
        source_root=args.source_root,
        signed_root=args.signed_root,
        rebuilt_root=args.rebuilt_root,
        test_report=args.test_report,
        output=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
