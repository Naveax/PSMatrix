from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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

from psmatrix import __version__
from psmatrix.deployment import build_windows_worker_package, verify_windows_worker_package
from psmatrix.lab_certification import build_certification_kit, verify_certification_kit
from psmatrix.lab_provisioning import build_provisioning_kit, verify_provisioning_kit
from psmatrix.release import (
    build_reproducible_source,
    create_release_manifest,
    release_files,
    verify_reproducible_build,
)
from psmatrix.util import atomic_write_json, sha256_file


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RC = re.compile(r"^2\.0\.0rc[0-9]+$")


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(command)
            + f"\nexit={completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _git_text(*args: str) -> str:
    return _run(["git", *args], cwd=ROOT).stdout.strip()


def _require_exact_clean_head(expected_head: str) -> str:
    expected = expected_head.strip().lower()
    if not _SHA40.fullmatch(expected):
        raise RuntimeError("--expected-head must be a full 40-character lowercase Git SHA")
    actual = _git_text("rev-parse", "HEAD").lower()
    if actual != expected:
        raise RuntimeError(f"Exact HEAD mismatch: expected {expected}, actual {actual}")
    dirty = _git_text("status", "--porcelain")
    if dirty:
        raise RuntimeError("Source checkout is not clean")
    return actual


def _project_version() -> str:
    value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(((value.get("project") or {}).get("version")) or "")
    if not version:
        raise RuntimeError("pyproject.toml project.version is missing")
    if version != __version__:
        raise RuntimeError(f"Version mismatch: pyproject={version}, package={__version__}")
    if not _RC.fullmatch(version):
        raise RuntimeError(f"Windows Authority staging requires a 2.0.0rcN version, got {version}")
    return version


def _ensure_output_outside_source(output_root: Path) -> Path:
    output = output_root.resolve()
    source = ROOT.resolve()
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise RuntimeError("Release staging output must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Release staging output must be empty: {output}")
    return output


def _copy_release_tree(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for source in release_files(ROOT):
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _wheel_build(build_tree: Path, wheel_dir: Path, version: str) -> Path:
    wheel_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "SOURCE_DATE_EPOCH": "0",
            "PYTHONHASHSEED": "0",
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
    )
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(build_tree),
        ],
        cwd=build_tree,
        env=env,
    )
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"Expected exactly one wheel, found {len(wheels)}")
    expected_name = f"psmatrix-{version}-py3-none-any.whl"
    if wheels[0].name != expected_name:
        raise RuntimeError(f"Unexpected wheel name: {wheels[0].name}; expected {expected_name}")
    return wheels[0]


def _artifact(path: Path) -> dict[str, Any]:
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _copy_verified(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if sha256_file(source) != sha256_file(destination) or source.stat().st_size != destination.stat().st_size:
        raise RuntimeError(f"Artifact copy verification failed: {source.name}")
    return destination


def build(expected_head: str, output_root: Path) -> dict[str, Any]:
    head = _require_exact_clean_head(expected_head)
    version = _project_version()
    output = _ensure_output_outside_source(output_root)
    name = f"psmatrix-{version}"

    previous_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "0"
    try:
        with tempfile.TemporaryDirectory(prefix="psmatrix-release-candidate-build-a-") as temp_a, tempfile.TemporaryDirectory(
            prefix="psmatrix-release-candidate-build-b-"
        ) as temp_b:
            root_a = Path(temp_a)
            root_b = Path(temp_b)
            source_a = root_a / "source"
            source_b = root_b / "source"

            source_result_a = build_reproducible_source(ROOT, source_a, name=name)
            source_result_b = build_reproducible_source(ROOT, source_b, name=name)
            source_zip_a = Path(source_result_a["zip"]["path"])
            source_zip_b = Path(source_result_b["zip"]["path"])
            source_tar_a = Path(source_result_a["tar_gz"]["path"])
            source_tar_b = Path(source_result_b["tar_gz"]["path"])
            source_zip_repro = verify_reproducible_build(source_zip_a, source_zip_b)
            source_tar_repro = verify_reproducible_build(source_tar_a, source_tar_b)

            tree_a = root_a / "build-tree"
            tree_b = root_b / "build-tree"
            _copy_release_tree(tree_a)
            _copy_release_tree(tree_b)
            wheel_a = _wheel_build(tree_a, root_a / "wheel", version)
            wheel_b = _wheel_build(tree_b, root_b / "wheel", version)
            wheel_repro = verify_reproducible_build(wheel_a, wheel_b)

            workers_a = root_a / f"{name}-windows-workers.zip"
            workers_b = root_b / f"{name}-windows-workers.zip"
            build_windows_worker_package(ROOT, workers_a, version=version, wheel=wheel_a)
            build_windows_worker_package(ROOT, workers_b, version=version, wheel=wheel_b)
            workers_repro = verify_reproducible_build(workers_a, workers_b)
            worker_verification = verify_windows_worker_package(workers_a)

            certification_a = root_a / f"{name}-windows-certification-kit.zip"
            certification_b = root_b / f"{name}-windows-certification-kit.zip"
            build_certification_kit(ROOT, certification_a, version=version)
            build_certification_kit(ROOT, certification_b, version=version)
            certification_repro = verify_reproducible_build(certification_a, certification_b)
            certification_verification = verify_certification_kit(certification_a)

            provisioning_a = root_a / f"{name}-windows-provisioning-kit.zip"
            provisioning_b = root_b / f"{name}-windows-provisioning-kit.zip"
            build_provisioning_kit(ROOT, provisioning_a, version=version)
            build_provisioning_kit(ROOT, provisioning_b, version=version)
            provisioning_repro = verify_reproducible_build(provisioning_a, provisioning_b)
            provisioning_verification = verify_provisioning_kit(provisioning_a)

            staged = [
                _copy_verified(wheel_a, output / wheel_a.name),
                _copy_verified(source_zip_a, output / source_zip_a.name),
                _copy_verified(source_tar_a, output / source_tar_a.name),
                _copy_verified(workers_a, output / workers_a.name),
                _copy_verified(certification_a, output / certification_a.name),
                _copy_verified(provisioning_a, output / provisioning_a.name),
            ]

        unsigned_manifest = output / f"{name}-release-unsigned.json"
        create_release_manifest(staged, unsigned_manifest, version=version)
        unsigned_value = json.loads(unsigned_manifest.read_text(encoding="utf-8"))
        if "attestation" in unsigned_value:
            raise RuntimeError("Unsigned release proposal unexpectedly contains an attestation")

        sums = output / "SHA256SUMS.txt"
        sums.write_text(
            "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(staged, key=lambda item: item.name)),
            encoding="utf-8",
            newline="\n",
        )

        report = {
            "schema": 1,
            "kind": "psmatrix.windows-authority-release-candidate-staging",
            "status": "READY_FOR_PROTECTED_SIGNING",
            "version": version,
            "release_commit": head,
            "source_root": str(ROOT.resolve()),
            "output_root": str(output),
            "source_date_epoch": 0,
            "artifacts": [_artifact(path) for path in sorted(staged, key=lambda item: item.name)],
            "reproducibility": {
                "wheel": wheel_repro,
                "source_zip": source_zip_repro,
                "source_tar_gz": source_tar_repro,
                "windows_workers": workers_repro,
                "windows_certification_kit": certification_repro,
                "windows_provisioning_kit": provisioning_repro,
            },
            "verification": {
                "windows_workers": worker_verification,
                "windows_certification_kit": certification_verification,
                "windows_provisioning_kit": provisioning_verification,
            },
            "unsigned_manifest_proposal": _artifact(unsigned_manifest),
            "sha256sums": _artifact(sums),
            "private_key_read": False,
            "signed_release_manifest_written": False,
            "downloads_files": False,
            "extracts_existing_operation_package": False,
            "authoritative": False,
            "ga_eligible": False,
            "next_required": [
                "Review this deterministic artifact set and its byte-for-byte reproducibility evidence.",
                f"Freeze a reviewed {version} staging lock before any protected release signing is permitted.",
                "Use only a protected release-signing authority whose public key is frozen by that reviewed staging lock.",
                "Verify the signed manifest with the frozen release public key before Windows Authority intake.",
            ],
        }
        report_path = output / f"{name}-windows-authority-staging.json"
        atomic_write_json(report_path, report)
        return report
    finally:
        if previous_epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous_epoch


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic unsigned Windows Authority RC release set")
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = build(args.expected_head, args.output_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
