#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OCI_TESTS = (
    "test_image_reference_validation",
    "test_install_pins_digest_and_probes_exact_version",
    "test_mutable_local_tag_requires_explicit_trust",
    "test_version_mismatch_is_rejected",
    "test_cli_executes_registered_oci_runtime",
)


def count_tests(path: Path) -> int:
    return len(re.findall(r"^\s+def test_", path.read_text(encoding="utf-8"), flags=re.MULTILINE))


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort cleanup for descendants that outlive the unittest process."""

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        return

    time.sleep(0.15)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run(command: list[str], *, root: Path, timeout: int) -> None:
    environment = dict(os.environ)
    source = str(root / "src")
    environment["PYTHONPATH"] = source + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    environment.setdefault("TERM", "dumb")

    # Every module receives a fresh user/temp/cache namespace. Test processes
    # therefore cannot affect later modules through default PSMatrix state,
    # stale lock files, module caches, or temporary runtime artefacts.
    isolated_root = tempfile.TemporaryDirectory(prefix="psmatrix-test-env-")
    isolated = Path(isolated_root.name)
    isolated.chmod(0o755)
    (isolated / "tmp").mkdir(mode=0o777)
    (isolated / "tmp").chmod(0o1777)
    (isolated / "cache").mkdir(mode=0o755)
    (isolated / "config").mkdir(mode=0o755)
    (isolated / "data").mkdir(mode=0o755)
    environment.update({
        "HOME": str(isolated),
        "TMPDIR": str(isolated / "tmp"),
        "TEMP": str(isolated / "tmp"),
        "TMP": str(isolated / "tmp"),
        "XDG_CACHE_HOME": str(isolated / "cache"),
        "XDG_CONFIG_HOME": str(isolated / "config"),
        "XDG_DATA_HOME": str(isolated / "data"),
        "PSMATRIX_HOME": str(isolated / "psmatrix-home"),
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "PYTHONNOUSERSITE": "1",
    })

    # On POSIX, coreutils timeout owns the complete child process group. This
    # avoids state accumulation in the long-lived Python supervisor and gives
    # deterministic TERM -> KILL escalation even when a test leaves descendants.
    effective_command = list(command)
    if os.name != "nt" and Path("/usr/bin/timeout").is_file():
        effective_command = [
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=5s",
            f"{timeout}s",
            *command,
        ]

    with tempfile.TemporaryFile(mode="w+b") as log:
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(
                effective_command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _terminate_process_tree(process)
                return_code = 124
        else:
            completed = subprocess.run(
                effective_command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
            return_code = completed.returncode

        log.flush()
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
        if output:
            sys.stdout.write(output)
            if not output.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()

        if return_code in {124, 137}:
            isolated_root.cleanup()
            print(f"Test command timed out after {timeout}s: {' '.join(command)}", file=sys.stderr)
            raise SystemExit(124)
        if return_code != 0:
            isolated_root.cleanup()
            raise SystemExit(return_code)
    isolated_root.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PSMatrix tests in isolated processes.")
    parser.add_argument("--timeout", type=int, default=240, help="Per module/test timeout in seconds")
    parser.add_argument("--skip-oci", action="store_true")
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if os.name != "nt" and os.environ.get("PSMATRIX_TEST_FORCE_PYTHON") != "1":
        posix_runner = root / "scripts" / "run_tests_posix.sh"
        os.execv(str(posix_runner), [str(posix_runner), *sys.argv[1:]])

    files = sorted(
        (root / "tests").glob("test_*.py"),
        key=lambda path: (path.name != "test_oci.py", path.name),
    )
    total = sum(count_tests(path) for path in files)
    passed = 0

    for path in files:
        module = f"tests.{path.stem}"
        if path.name == "test_oci.py":
            if arguments.skip_oci:
                continue
            for name in OCI_TESTS:
                print(f"== {module}.OciRuntimeTests.{name} ==", flush=True)
                run(
                    [sys.executable, "-m", "unittest", f"{module}.OciRuntimeTests.{name}", "-v"],
                    root=root,
                    timeout=arguments.timeout,
                )
                passed += 1
            continue
        print(f"== {module} ==", flush=True)
        run([sys.executable, "-m", "unittest", module, "-v"], root=root, timeout=arguments.timeout)
        passed += count_tests(path)

    expected = total - (len(OCI_TESTS) if arguments.skip_oci else 0)
    if passed != expected:
        print(f"Test accounting mismatch: expected {expected}, passed {passed}", file=sys.stderr)
        return 2
    print(f"PSMatrix tests: {passed}/{expected} PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
