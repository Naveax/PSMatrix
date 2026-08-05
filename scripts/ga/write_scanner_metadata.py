#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path


def version(command: list[str]) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    value = (completed.stdout or completed.stderr).strip().splitlines()
    if not value:
        raise RuntimeError(f"command returned no version: {command}")
    return value[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file() or wheel.is_symlink():
        raise SystemExit("release wheel is missing or unsafe")
    result = {
        "schema": 1,
        "commit_sha": args.commit_sha,
        "wheel_name": wheel.name,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_size": wheel.stat().st_size,
        "python_version": platform.python_version(),
        "bandit_version": version(["bandit", "--version"]),
        "pip_audit_version": version(["pip-audit", "--version"]),
        "scanner_packages": [
            {
                "name": "bandit",
                "version": "1.9.4",
                "wheel_sha256": "f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e",
            },
            {
                "name": "pip-audit",
                "version": "2.10.1",
                "wheel_sha256": "99ef3f600a317c1945f1e89e227ef26e1c2d618429b8bd3fa6f4f7c440c4611a",
            },
        ],
        "installed_packages": sorted(
            subprocess.run(
                ["python", "-m", "pip", "freeze", "--all"],
                check=True, capture_output=True, text=True, timeout=60,
            ).stdout.splitlines()
        ),
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
