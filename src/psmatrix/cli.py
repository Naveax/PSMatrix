from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .catalog import (
    BUILTIN_CHANNELS,
    CORE_RELEASE_LINES,
    MATRICES,
    matrix_versions,
    release_metadata,
    resolve_runtime,
)
from .dependencies import load_dependency_lock
from .cache import ResultCache, engine_fingerprint, installed_modules_fingerprint
from .evidence import write_evidence_bundle
from .attestation import build_slsa_provenance, load_attestation, sign_provenance, verify_provenance, write_attestation
from .exporters import write_html, write_junit, write_sarif
from .differential import compare_targets
from .diagnostics import collect_diagnostics, report_diagnostics
from .errors import PSMatrixError
from .gate import create_gate_receipt, load_gate_receipt, verify_gate_receipt, write_gate_receipt
from .models import MatrixReport
from .oci import OCI_IMAGE_CANDIDATES, OciRuntimeManager, detect_container_engines
from .module_manager import ModuleManager
from .module_compat import OfflineModuleMirror, execute_compatibility_matrix, plan_compatibility_matrix, resolve_mirror_lock, scan_project_dependencies, write_compatibility_template
from .report import render_human
from .repair import apply_and_validate, build_repair_plan, propose_patch, resolve_project_file
from .runner import RunOptions, ScriptRunner
from .scheduler import CheckpointStore, build_jobs, execute_jobs
from .runtime import RuntimeManager, detect_host_abi, normalize_arch
from .sandbox import detect_capabilities
from .scanner import scan_powershell_files
from .sbom import write_sbom
from .mcp_server import serve_stdio
from .http_auth import HTTPAuthConfig
from .http_mcp import HTTPMCPConfig, serve_http
from .http_sessions import SessionLimits
from .web_bootstrap import build_web_ai_bundle
from .observability import ObservabilityService, OTLPMetricsExporter
from .signing import TrustStore, generate_ed25519_keypair
from .remote_worker import RemoteEndpoint, WindowsJobExecutor, WorkerConfig, certificate_sha256, probe_remote_endpoint, serve_worker, submit_remote_job
from .fleet import FleetRegistry
from .fleet_runner import execute_managed_fleet_job, probe_fleet_worker
from .fleet_queue import FleetQueue
from .queue_runner import serve_queue
from .snapshot_adapter import SnapshotAdapter, SnapshotAdapterConfig, verify_snapshot_attestation
from .pki import apply_rotation_bundle, create_ca, create_rotation_bundle, inspect_certificate, issue_certificate
from .deployment import build_windows_worker_package, verify_windows_worker_package
from .release import build_reproducible_source, create_release_manifest, verify_release_manifest, verify_reproducible_build
from .hybrid import execute_hybrid_matrix
from .full_matrix import execute_full_matrix, plan_full_matrix, write_full_matrix_template
from .full_matrix_ga import (
    build_full_matrix_release_binding,
    create_full_matrix_ga_attestation,
    verify_full_matrix_ga_attestation,
)
from .lab_certification import (
    build_certification_kit,
    certify_remote_windows_image,
    verify_certification_attestation,
    verify_certification_kit,
    run_certification_campaign,
    verify_campaign_attestation,
)
from .lab_provisioning import (
    build_provision_plan,
    build_provisioning_kit,
    build_windows_release_binding,
    lab_profiles,
    provision_remote_hyperv_lab,
    run_authoritative_matrix,
    verify_authoritative_matrix_attestation,
    verify_provisioning_kit,
)
from .util import atomic_write_json, utc_now_iso
from .adversarial import list_adversarial_cases, run_adversarial_campaign
from .recovery import (
    QueueRecovery,
    RecoveryJournal,
    TransferRecovery,
    list_recovery_cases,
    run_recovery_campaign,
    sign_recovery_report,
    verify_recovery_report,
    write_recovery_evidence,
)
from .transfer import TransferStore
from .security_review import build_security_review_packet, finalize_security_review
from .ga import (
    create_ga_artifact_attestation,
    create_ga_attestation,
    create_ga_proof,
    evaluate_ga,
    run_key_rotation_drill,
    sign_ga_policy,
    verify_ga_artifact_attestation,
    verify_ga_attestation,
    verify_ga_proof,
    write_ga_template,
)


def default_home() -> Path:
    return Path(os.environ.get("PSMATRIX_HOME", Path.home() / ".cache" / "psmatrix"))




def _split_assignment(value: str, *, label: str) -> tuple[str, str]:
    if "=" not in value:
        raise PSMatrixError(f"{label} must use NAME=VALUE syntax: {value!r}")
    name, raw = value.split("=", 1)
    if not name:
        raise PSMatrixError(f"{label} name cannot be empty")
    return name, raw


def _parse_string_assignments(values: list[str], *, label: str) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value in values:
        name, raw = _split_assignment(value, label=label)
        key = name.casefold()
        if key in seen:
            raise PSMatrixError(f"Duplicate {label} assignment: {name}")
        seen.add(key)
        result.append((name, raw))
    return tuple(result)


def _parse_json_assignments(values: list[str]) -> tuple[tuple[str, object], ...]:
    result: list[tuple[str, object]] = []
    seen: set[str] = set()
    for value in values:
        name, raw = _split_assignment(value, label="--param-json")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PSMatrixError(f"Invalid JSON value for parameter {name}: {exc}") from exc
        key = name.casefold()
        if key in seen:
            raise PSMatrixError(f"Duplicate parameter assignment: {name}")
        seen.add(key)
        result.append((name, parsed))
    return tuple(result)


def _load_env_file(path: Path) -> list[str]:
    path = path.resolve()
    if not path.is_file():
        raise PSMatrixError(f"Environment file not found: {path}")
    result: list[str] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise PSMatrixError(f"Invalid environment file line {index}: expected NAME=VALUE")
        name, value = stripped.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result.append(name.strip() + "=" + value)
    return result


def _parse_fixture_values(values: list[str]) -> tuple[tuple[str, str | None], ...]:
    result: list[tuple[str, str | None]] = []
    for value in values:
        if "=" in value:
            source, destination = value.split("=", 1)
            if not source or not destination:
                raise PSMatrixError("--fixture must use SOURCE or SOURCE=DESTINATION")
            result.append((source, destination))
        else:
            if not value:
                raise PSMatrixError("--fixture source cannot be empty")
            result.append((value, None))
    return tuple(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="psmatrix")
    parser.add_argument("--home", type=Path, default=default_home())
    parser.add_argument("--version", action="version", version=f"PSMatrix {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Inspect the Bash environment and PSMatrix state")

    runtime = sub.add_parser("runtime", help="Manage portable PowerShell runtimes")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_sub.add_parser("list")
    install = runtime_sub.add_parser("install")
    install.add_argument("version", help="Exact version or channel: stable/lts/preview")
    install.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    install.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    install.add_argument("--force", action="store_true")
    install.add_argument("--archive", type=Path, help="Install from a local official tar.gz archive")
    hash_group = install.add_mutually_exclusive_group()
    hash_group.add_argument("--sha256", help="Expected SHA-256 for --archive")
    hash_group.add_argument(
        "--hashes-file",
        type=Path,
        help="Official hashes.sha256 file (UTF-8 or UTF-16)",
    )
    remove = runtime_sub.add_parser("remove")
    remove.add_argument("version")
    remove.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    remove.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    verify_runtime = runtime_sub.add_parser("verify")
    verify_runtime.add_argument("version")
    verify_runtime.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    verify_runtime.add_argument("--libc", choices=["glibc", "musl"], default="glibc")

    oci_install = runtime_sub.add_parser(
        "oci-install", help="Register an exact PowerShell runtime through Docker/Podman"
    )
    oci_install.add_argument("version")
    oci_install.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    oci_install.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    oci_install.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto")
    oci_install.add_argument("--image", help="Exact OCI image reference; defaults to the historical candidate catalog")
    oci_install.add_argument("--image-digest", help="Expected immutable image digest: sha256:<hex>")
    oci_install.add_argument("--no-pull", action="store_true")
    oci_install.add_argument("--trust-local-image", action="store_true")
    oci_install.add_argument("--force", action="store_true")

    oci_verify = runtime_sub.add_parser("oci-verify")
    oci_verify.add_argument("version")
    oci_verify.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    oci_verify.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    oci_verify.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto")

    oci_remove = runtime_sub.add_parser("oci-remove")
    oci_remove.add_argument("version")
    oci_remove.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    oci_remove.add_argument("--libc", choices=["glibc", "musl"], default="glibc")

    install_matrix = runtime_sub.add_parser(
        "install-matrix", help="Install every exact runtime in a named matrix"
    )
    install_matrix.add_argument("matrix", choices=sorted(MATRICES))
    install_matrix.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    install_matrix.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    install_matrix.add_argument("--force", action="store_true")
    install_matrix.add_argument("--backend", choices=["auto", "native", "oci"], default="auto")
    install_matrix.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto")

    module = sub.add_parser("module", help="Manage locally supplied PowerShell tool modules")
    module_sub = module.add_subparsers(dest="module_command", required=True)
    module_list = module_sub.add_parser("list")
    module_list.add_argument("name", nargs="?")
    module_install = module_sub.add_parser("install-nupkg")
    module_install.add_argument("package", type=Path)
    module_install.add_argument("--name")
    module_install.add_argument("--module-version")
    module_install.add_argument("--force", action="store_true")
    module_trust = module_install.add_mutually_exclusive_group(required=True)
    module_trust.add_argument("--sha256")
    module_trust.add_argument("--trust-local", action="store_true")
    module_lock = module_sub.add_parser("lock", help="Write exact installed module versions and package hashes")
    module_lock.add_argument("--name", action="append", default=[], help="Lock the latest installed version")
    module_lock.add_argument("--module", action="append", default=[], help="Lock an exact installed NAME=VERSION")
    module_lock.add_argument("--output", type=Path, default=Path("psmatrix.lock.json"))
    module_lock.add_argument("--require-verified", action="store_true")

    mirror = sub.add_parser("mirror", help="Manage an immutable offline PowerShell module mirror")
    mirror_sub = mirror.add_subparsers(dest="mirror_command", required=True)
    mirror_add = mirror_sub.add_parser("add")
    mirror_add.add_argument("package", type=Path)
    mirror_add.add_argument("--sha256", required=True)
    mirror_add.add_argument("--root", type=Path)
    mirror_add.add_argument("--source", default="manual")
    mirror_list = mirror_sub.add_parser("list")
    mirror_list.add_argument("name", nargs="?")
    mirror_list.add_argument("--root", type=Path)
    mirror_verify = mirror_sub.add_parser("verify")
    mirror_verify.add_argument("--root", type=Path)
    mirror_export = mirror_sub.add_parser("export")
    mirror_export.add_argument("--root", type=Path)
    mirror_export.add_argument("--output", type=Path, required=True)
    mirror_install = mirror_sub.add_parser("install")
    mirror_install.add_argument("name")
    mirror_install.add_argument("version")
    mirror_install.add_argument("--root", type=Path)
    mirror_lock = mirror_sub.add_parser("lock")
    mirror_lock.add_argument("--module", action="append", required=True, help="Exact root NAME=VERSION")
    mirror_lock.add_argument("--root", type=Path)
    mirror_lock.add_argument("--output", type=Path, default=Path("psmatrix.lock.json"))

    compat = sub.add_parser("compat", help="Plan module and project compatibility laboratories")
    compat_sub = compat.add_subparsers(dest="compat_command", required=True)
    compat_init = compat_sub.add_parser("init")
    compat_init.add_argument("--output", type=Path, default=Path("psmatrix.compat.json"))
    compat_scan = compat_sub.add_parser("scan")
    compat_scan.add_argument("path", type=Path, nargs="?", default=Path.cwd())
    compat_scan.add_argument("--output", type=Path)
    compat_plan = compat_sub.add_parser("plan")
    compat_plan.add_argument("--spec", type=Path, required=True)
    compat_plan.add_argument("--mirror-root", type=Path)
    compat_plan.add_argument("--output", type=Path)
    compat_run = compat_sub.add_parser("run")
    compat_run.add_argument("--spec", type=Path, required=True)
    compat_run.add_argument("--mirror-root", type=Path)
    compat_run.add_argument("--output", type=Path, required=True)
    compat_run.add_argument("--timeout", type=float, default=120.0)

    dependency = sub.add_parser("dependency", help="Validate and initialize reproducible dependency locks")
    dependency_sub = dependency.add_subparsers(dest="dependency_command", required=True)
    dependency_validate = dependency_sub.add_parser("validate")
    dependency_validate.add_argument("lockfile", type=Path)
    dependency_init = dependency_sub.add_parser("init")
    dependency_init.add_argument("--output", type=Path, default=Path("psmatrix.lock.json"))
    dependency_init.add_argument("--force", action="store_true")

    cache_cmd = sub.add_parser("cache", help="Inspect and maintain incremental result cache")
    cache_sub = cache_cmd.add_subparsers(dest="cache_command", required=True)
    cache_stats = cache_sub.add_parser("stats")
    cache_stats.add_argument("--cache-dir", type=Path)
    cache_clear = cache_sub.add_parser("clear")
    cache_clear.add_argument("--cache-dir", type=Path)
    cache_prune = cache_sub.add_parser("prune")
    cache_prune.add_argument("--cache-dir", type=Path)
    cache_prune.add_argument("--max-age-days", type=float)
    cache_prune.add_argument("--max-records", type=int)

    scan = sub.add_parser("scan", help="Find PowerShell source files")
    scan.add_argument("path", type=Path, nargs="?", default=Path.cwd())
    scan.add_argument("--json", action="store_true")

    test = sub.add_parser("test", help="Parse, execute, and verify PowerShell files")
    test.add_argument("paths", type=Path, nargs="+")
    test.add_argument("--runtime", action="append", default=[])
    test.add_argument("--matrix", choices=sorted(MATRICES))
    test.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    test.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    test.add_argument(
        "--backend", choices=["auto", "native", "oci"], default="auto",
        help="auto prefers native and falls back to a registered OCI runtime",
    )
    test.add_argument(
        "--container-engine", choices=["auto", "docker", "podman"], default="auto"
    )
    test.add_argument("--install-missing", action="store_true")
    test.add_argument("--timeout", type=float, default=60.0)
    test.add_argument("--max-output-mib", type=int, default=10)
    test.add_argument(
        "--sandbox",
        choices=["auto", "strict", "copy", "direct"],
        default="auto",
        help="strict requires strong isolation; auto uses the strongest available guarded backend",
    )
    test.add_argument("--network", choices=["none", "host"], default="none")
    test.add_argument("--max-file-mib", type=int, default=256)
    test.add_argument("--max-workspace-mib", type=int, default=512)
    test.add_argument("--max-memory-mib", type=int, default=1024)
    test.add_argument(
        "--max-committed-memory-mib",
        type=int,
        default=None,
        help=(
            "Optional Windows Job Object committed-memory budget; distinct "
            "from sampled RSS/working-set max-memory"
        ),
    )
    test.add_argument("--max-processes", type=int, default=128)
    test.add_argument("--max-open-files", type=int, default=512)
    test.add_argument(
        "--psscriptanalyzer",
        choices=["auto", "required", "off"],
        default="auto",
        help="Use an installed PSScriptAnalyzer module; required fails closed when unavailable",
    )
    test.add_argument(
        "--analyzer-fail-on",
        choices=["error", "warning", "information", "none"],
        default="error",
        help="Lowest PSScriptAnalyzer severity that fails the target",
    )
    test.add_argument(
        "--pester",
        choices=["auto", "required", "off"],
        default="auto",
        help="Discover and run matching Pester tests when an installed Pester module is available",
    )
    test.add_argument(
        "--coverage",
        choices=["auto", "required", "off"],
        default="auto",
        help="Collect Pester code coverage when supported; required fails closed",
    )
    test.add_argument(
        "--coverage-fail-under",
        type=float,
        help="Fail when structured code coverage is below this percentage",
    )
    test.add_argument(
        "--native-exit",
        choices=["auto", "required", "off"],
        default="auto",
        help="Validate the final observed native-command $LASTEXITCODE",
    )
    test.add_argument(
        "--stream-errors",
        choices=["auto", "strict", "off"],
        default="auto",
        help="Fail on PowerShell error-stream records unless explicitly contracted",
    )
    test.add_argument("--arg", action="append", default=[], help="Positional PowerShell argument; repeatable")
    test.add_argument("--param", action="append", default=[], help="String parameter using NAME=VALUE")
    test.add_argument("--param-json", action="append", default=[], help="Typed parameter using NAME=JSON")
    test.add_argument("--env", action="append", default=[], help="Explicit environment variable using NAME=VALUE")
    test.add_argument("--env-file", action="append", type=Path, default=[], help="Strict UTF-8 NAME=VALUE file")
    stdin_group = test.add_mutually_exclusive_group()
    stdin_group.add_argument("--stdin-text")
    stdin_group.add_argument("--stdin-file", type=Path)
    test.add_argument("--fixture", action="append", default=[], help="SOURCE or SOURCE=workspace/destination")
    test.add_argument("--setup", action="append", default=[], help="PowerShell setup hook; repeatable")
    test.add_argument("--teardown", action="append", default=[], help="PowerShell teardown hook; repeatable")
    test.add_argument("--lockfile", type=Path, help="Exact dependency lockfile; defaults to psmatrix.lock.json")
    test.add_argument(
        "--dependencies",
        choices=["auto", "required", "off"],
        default="auto",
        help="Resolve exact module/native dependencies; required fails when lockfile is absent",
    )
    test.add_argument("--keep-sandbox", action="store_true")
    test.add_argument(
        "--differential",
        choices=["auto", "off", "report", "strict"],
        default="auto",
        help="Compare runtime results; strict turns any difference into a failure",
    )
    test.add_argument(
        "--baseline-runtime",
        help="Exact runtime version or runtime id used as the differential baseline",
    )
    test.add_argument("--jobs", type=int, default=0, help="Parallel target workers; 0 chooses automatically")
    test.add_argument("--fail-fast", action="store_true", help="Stop scheduling new targets after the first failure")
    test.add_argument("--shard-index", type=int, default=0, help="Zero-based deterministic shard index")
    test.add_argument("--shard-count", type=int, default=1, help="Total deterministic shard count")
    test.add_argument("--cache", choices=["auto", "off", "refresh"], default="auto")
    test.add_argument("--cache-dir", type=Path, help="Result cache directory; defaults under PSMATRIX_HOME")
    test.add_argument("--checkpoint", type=Path, help="Atomically persist completed target results")
    test.add_argument("--resume", type=Path, help="Resume from and continue writing a checkpoint file")
    test.add_argument("--report-json", type=Path)
    test.add_argument("--report-junit", type=Path)
    test.add_argument("--report-sarif", type=Path)
    test.add_argument("--report-html", type=Path)
    test.add_argument("--report-sbom", type=Path)
    test.add_argument("--evidence-bundle", type=Path)
    test.add_argument("--attestation", type=Path, help="Write a DSSE-signed SLSA provenance envelope for --evidence-bundle")
    test.add_argument("--signing-private-key", type=Path)
    test.add_argument("--signing-public-key", type=Path)
    test.add_argument("--builder-id", help="Stable builder URI used in signed provenance")
    test.add_argument("--json", action="store_true")

    plan = sub.add_parser("plan", help="Plan a runtime matrix without executing source code")
    plan.add_argument("--runtime", action="append", default=[])
    plan.add_argument("--matrix", choices=sorted(MATRICES), default="default")
    plan.add_argument("--arch", choices=["x64", "arm64", "arm32"])
    plan.add_argument("--libc", choices=["glibc", "musl"], default="glibc")
    plan.add_argument("--backend", choices=["auto", "native", "oci"], default="auto")
    plan.add_argument("--container-engine", choices=["auto", "docker", "podman"], default="auto")

    diagnose = sub.add_parser("diagnose", help="Normalize a PSMatrix report into stable diagnostic codes")
    diagnose.add_argument("report", type=Path)
    diagnose.add_argument("--json", action="store_true")

    repair = sub.add_parser("repair", help="Create and validate transactional repair patches")
    repair_sub = repair.add_subparsers(dest="repair_command", required=True)
    repair_plan = repair_sub.add_parser("plan")
    repair_plan.add_argument("report", type=Path)
    repair_plan.add_argument("--root", type=Path, default=Path.cwd())
    repair_plan.add_argument("--output", type=Path, required=True)
    repair_plan.add_argument("--validation-arg", action="append", default=[])
    repair_plan.add_argument("--validation-file", type=Path)
    repair_propose = repair_sub.add_parser("propose")
    repair_propose.add_argument("proposal", type=Path)
    repair_propose.add_argument("--root", type=Path, default=Path.cwd())
    repair_propose.add_argument("--plan", type=Path, required=True)
    repair_propose.add_argument("--output", type=Path, required=True)
    repair_apply = repair_sub.add_parser("apply")
    repair_apply.add_argument("bundle", type=Path)
    repair_apply.add_argument("--root", type=Path, default=Path.cwd())
    repair_apply.add_argument("--session", type=Path, default=Path(".psmatrix/repair-session.json"))
    repair_apply.add_argument("--receipt", type=Path, default=Path(".psmatrix/delivery-gate.json"))
    repair_apply.add_argument("--max-attempts", type=int, default=3)
    repair_apply.add_argument("--validation-arg", action="append", default=[])
    repair_apply.add_argument("--validation-file", type=Path)

    gate = sub.add_parser("gate", help="Verify signed delivery test receipts")
    gate_sub = gate.add_subparsers(dest="gate_command", required=True)
    gate_issue = gate_sub.add_parser("issue")
    gate_issue.add_argument("report", type=Path)
    gate_issue.add_argument("--root", type=Path, default=Path.cwd())
    gate_issue.add_argument("--output", type=Path, default=Path(".psmatrix/delivery-gate.json"))
    gate_verify = gate_sub.add_parser("verify")
    gate_verify.add_argument("receipt", type=Path)
    gate_verify.add_argument("--root", type=Path, default=Path.cwd())

    trust = sub.add_parser("trust", help="Manage externally verifiable Ed25519 trust identities")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)
    trust_keygen = trust_sub.add_parser("keygen")
    trust_keygen.add_argument("--private-key", type=Path, required=True)
    trust_keygen.add_argument("--public-key", type=Path, required=True)
    trust_keygen.add_argument("--force", action="store_true")
    trust_add = trust_sub.add_parser("add")
    trust_add.add_argument("--identity", required=True)
    trust_add.add_argument("--role", choices=["controller", "worker", "release"], required=True)
    trust_add.add_argument("--public-key", type=Path, required=True)
    trust_add.add_argument("--certificate", type=Path)
    trust_add.add_argument("--replace", action="store_true")
    trust_rotate = trust_sub.add_parser("rotate")
    trust_rotate.add_argument("--identity", required=True)
    trust_rotate.add_argument("--role", choices=["controller", "worker", "release"], required=True)
    trust_rotate.add_argument("--public-key", type=Path, required=True)
    trust_rotate.add_argument("--certificate", type=Path)
    trust_rotate.add_argument("--expected-current-key-id")
    trust_revoke = trust_sub.add_parser("revoke")
    trust_revoke.add_argument("--identity", required=True)
    trust_revoke.add_argument("--role", choices=["controller", "worker", "release"], required=True)
    trust_revoke.add_argument("--reason", required=True)
    trust_sub.add_parser("list")

    attest = sub.add_parser("attest", help="Create and verify DSSE-wrapped SLSA provenance")
    attest_sub = attest.add_subparsers(dest="attest_command", required=True)
    attest_create = attest_sub.add_parser("create")
    attest_create.add_argument("--artifact", type=Path, required=True)
    attest_create.add_argument("--report", type=Path, required=True)
    attest_create.add_argument("--builder-id", required=True)
    attest_create.add_argument("--worker-identity")
    attest_create.add_argument("--private-key", type=Path, required=True)
    attest_create.add_argument("--public-key", type=Path, required=True)
    attest_create.add_argument("--output", type=Path, required=True)
    attest_verify = attest_sub.add_parser("verify")
    attest_verify.add_argument("attestation", type=Path)
    attest_verify.add_argument("--public-key", type=Path, required=True)
    attest_verify.add_argument("--artifact", type=Path)

    pki = sub.add_parser("pki", help="Create and rotate worker mutual-TLS credentials")
    pki_sub = pki.add_subparsers(dest="pki_command", required=True)
    pki_ca = pki_sub.add_parser("create-ca")
    pki_ca.add_argument("--output", type=Path, required=True)
    pki_ca.add_argument("--common-name", required=True)
    pki_ca.add_argument("--days", type=int, default=3650)
    pki_ca.add_argument("--force", action="store_true")
    pki_issue = pki_sub.add_parser("issue")
    pki_issue.add_argument("--ca-certificate", type=Path, required=True)
    pki_issue.add_argument("--ca-private-key", type=Path, required=True)
    pki_issue.add_argument("--output", type=Path, required=True)
    pki_issue.add_argument("--common-name", required=True)
    pki_issue.add_argument("--role", choices=["server", "client"], required=True)
    pki_issue.add_argument("--dns-name", action="append", default=[])
    pki_issue.add_argument("--days", type=int, default=90)
    pki_issue.add_argument("--force", action="store_true")
    pki_inspect = pki_sub.add_parser("inspect")
    pki_inspect.add_argument("certificate", type=Path)
    pki_rotation = pki_sub.add_parser("create-rotation")
    pki_rotation.add_argument("--output", type=Path, required=True)
    pki_rotation.add_argument("--identity", required=True)
    pki_rotation.add_argument("--role", choices=["worker-server", "controller-client"], required=True)
    pki_rotation.add_argument("--certificate", type=Path, required=True)
    pki_rotation.add_argument("--private-key", type=Path, required=True)
    pki_rotation.add_argument("--ca-certificate", type=Path, required=True)
    pki_rotation.add_argument("--signing-private-key", type=Path, required=True)
    pki_rotation.add_argument("--signing-public-key", type=Path, required=True)
    pki_rotation.add_argument("--generation", type=int, required=True)
    pki_apply = pki_sub.add_parser("apply-rotation")
    pki_apply.add_argument("bundle", type=Path)
    pki_apply.add_argument("--destination", type=Path, required=True)
    pki_apply.add_argument("--public-key", type=Path, required=True)
    pki_apply.add_argument("--identity", required=True)
    pki_apply.add_argument("--role", choices=["worker-server", "controller-client"], required=True)
    pki_apply.add_argument("--minimum-days", type=int, default=1)

    snapshot = sub.add_parser("snapshot", help="Run and verify signed hypervisor snapshot resets")
    snapshot_sub = snapshot.add_subparsers(dest="snapshot_command", required=True)
    snapshot_restore = snapshot_sub.add_parser("restore")
    snapshot_restore.add_argument("--config", type=Path, required=True)
    snapshot_restore.add_argument("--phase", choices=["before", "after", "maintenance"], required=True)
    snapshot_restore.add_argument("--private-key", type=Path, required=True)
    snapshot_restore.add_argument("--public-key", type=Path, required=True)
    snapshot_restore.add_argument("--output", type=Path)
    snapshot_verify = snapshot_sub.add_parser("verify")
    snapshot_verify.add_argument("attestation", type=Path)
    snapshot_verify.add_argument("--public-key", type=Path, required=True)
    snapshot_verify.add_argument("--worker-id", required=True)
    snapshot_verify.add_argument("--vm-id", required=True)
    snapshot_verify.add_argument("--snapshot-id", required=True)
    snapshot_verify.add_argument("--phase", choices=["before", "after", "maintenance"], required=True)

    fleet = sub.add_parser("fleet", help="Enroll, quarantine, select, and run trusted Windows workers")
    fleet_sub = fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_enroll = fleet_sub.add_parser("enroll")
    fleet_enroll.add_argument("endpoint", type=Path)
    fleet_enroll.add_argument("--label", action="append", default=[])
    fleet_enroll.add_argument("--priority", type=int, default=100)
    fleet_enroll.add_argument("--replace", action="store_true")
    fleet_enroll.add_argument("--snapshot-config", type=Path)
    fleet_enroll.add_argument("--reset-private-key", type=Path)
    fleet_enroll.add_argument("--reset-public-key", type=Path)
    fleet_list = fleet_sub.add_parser("list")
    fleet_list.add_argument("--all", action="store_true")
    fleet_health = fleet_sub.add_parser("health")
    fleet_health.add_argument("worker_id")
    fleet_health.add_argument("--timeout", type=int, default=30)
    fleet_health.add_argument("--quarantine-threshold", type=int, default=3)
    for action in ("quarantine", "activate", "revoke"):
        item = fleet_sub.add_parser(action)
        item.add_argument("worker_id")
        item.add_argument("--reason", required=True)
    fleet_select = fleet_sub.add_parser("select")
    fleet_select.add_argument("runtime_id")
    fleet_select.add_argument("--label", action="append", default=[])
    fleet_select.add_argument("--count", type=int, default=1)
    fleet_select.add_argument("--allow-unprobed", action="store_true")
    fleet_test = fleet_sub.add_parser("test")
    fleet_test.add_argument("entrypoint", type=Path)
    fleet_test.add_argument("--root", type=Path, default=Path.cwd())
    fleet_test.add_argument("--worker-id")
    fleet_test.add_argument("--runtime-id")
    fleet_test.add_argument("--label", action="append", default=[])
    fleet_test.add_argument("--include", type=Path, action="append", default=[])
    fleet_test.add_argument("--options", type=Path)
    fleet_test.add_argument("--report-json", type=Path)
    fleet_test.add_argument("--timeout", type=int, default=1200)
    queue_enqueue = fleet_sub.add_parser("queue-enqueue")
    queue_enqueue.add_argument("--runtime-id", required=True)
    queue_enqueue.add_argument("--payload", type=Path, required=True)
    queue_enqueue.add_argument("--idempotency-key")
    queue_enqueue.add_argument("--priority", type=int, default=100)
    queue_enqueue.add_argument("--max-attempts", type=int, default=3)
    queue_claim = fleet_sub.add_parser("queue-claim")
    queue_claim.add_argument("--owner", required=True)
    queue_claim.add_argument("--runtime-id", action="append", required=True)
    queue_claim.add_argument("--lease-seconds", type=int, default=300)
    queue_heartbeat = fleet_sub.add_parser("queue-heartbeat")
    queue_heartbeat.add_argument("job_id")
    queue_heartbeat.add_argument("--owner", required=True)
    queue_heartbeat.add_argument("--lease-seconds", type=int, default=300)
    queue_complete = fleet_sub.add_parser("queue-complete")
    queue_complete.add_argument("job_id")
    queue_complete.add_argument("--owner", required=True)
    queue_complete.add_argument("--result", type=Path, required=True)
    queue_fail = fleet_sub.add_parser("queue-fail")
    queue_fail.add_argument("job_id")
    queue_fail.add_argument("--owner", required=True)
    queue_fail.add_argument("--error", required=True)
    queue_fail.add_argument("--no-retry", action="store_true")
    queue_list = fleet_sub.add_parser("queue-list")
    queue_list.add_argument("--state", choices=["QUEUED", "LEASED", "COMPLETE", "FAILED"])
    queue_list.add_argument("--limit", type=int, default=100)
    queue_run = fleet_sub.add_parser("queue-run")
    queue_run.add_argument("--owner", required=True)
    queue_run.add_argument("--runtime-id", action="append", required=True)
    queue_run.add_argument("--lease-seconds", type=int, default=300)
    queue_run.add_argument("--timeout", type=int, default=1200)
    queue_run.add_argument("--quarantine-threshold", type=int, default=3)
    queue_run.add_argument("--poll-seconds", type=float, default=2.0)
    queue_run.add_argument("--max-jobs", type=int)
    queue_run.add_argument("--recovery-journal", type=Path, help="Hash-chained controller recovery journal; defaults under PSMatrix home")

    deploy = sub.add_parser("deploy", help="Build or verify Windows worker deployment packages")
    deploy_sub = deploy.add_subparsers(dest="deploy_command", required=True)
    deploy_build = deploy_sub.add_parser("windows-package")
    deploy_build.add_argument("--source-root", type=Path, default=Path.cwd())
    deploy_build.add_argument("--output", type=Path, required=True)
    deploy_build.add_argument("--wheel", type=Path)
    deploy_build.add_argument("--signing-private-key", type=Path)
    deploy_build.add_argument("--signing-public-key", type=Path)
    deploy_verify = deploy_sub.add_parser("verify")
    deploy_verify.add_argument("package", type=Path)
    deploy_verify.add_argument("--public-key", type=Path)

    lab = sub.add_parser("lab", help="Build and verify authoritative Windows image certification")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    lab_build = lab_sub.add_parser("build-kit")
    lab_build.add_argument("--source-root", type=Path, default=Path.cwd())
    lab_build.add_argument("--output", type=Path, required=True)
    lab_build.add_argument("--signing-private-key", type=Path)
    lab_build.add_argument("--signing-public-key", type=Path)
    lab_verify_kit = lab_sub.add_parser("verify-kit")
    lab_verify_kit.add_argument("package", type=Path)
    lab_verify_kit.add_argument("--public-key", type=Path)
    lab_certify = lab_sub.add_parser("certify")
    lab_certify.add_argument("--endpoint", type=Path, required=True)
    lab_certify.add_argument("--image-manifest", type=Path, required=True)
    lab_certify.add_argument("--fixture-root", type=Path, required=True)
    lab_certify.add_argument("--private-key", type=Path, required=True)
    lab_certify.add_argument("--public-key", type=Path, required=True)
    lab_certify.add_argument("--output", type=Path, required=True)
    lab_certify.add_argument("--timeout", type=int, default=1800)
    lab_verify = lab_sub.add_parser("verify-certification")
    lab_verify.add_argument("attestation", type=Path)
    lab_verify.add_argument("--public-key", type=Path, required=True)
    lab_verify.add_argument("--image-manifest", type=Path, required=True)
    lab_verify.add_argument("--fixture-root", type=Path, required=True)
    lab_campaign = lab_sub.add_parser("campaign")
    lab_campaign.add_argument("--endpoint", type=Path, required=True)
    lab_campaign.add_argument("--image-manifest", type=Path, required=True)
    lab_campaign.add_argument("--fixture-root", type=Path, required=True)
    lab_campaign.add_argument("--private-key", type=Path, required=True)
    lab_campaign.add_argument("--public-key", type=Path, required=True)
    lab_campaign.add_argument("--output-dir", type=Path, required=True)
    lab_campaign.add_argument("--campaign-output", type=Path, required=True)
    lab_campaign.add_argument("--campaign-id", required=True)
    lab_campaign.add_argument("--iterations", type=int, default=3)
    lab_campaign.add_argument("--timeout", type=int, default=1800)
    lab_verify_campaign = lab_sub.add_parser("verify-campaign")
    lab_verify_campaign.add_argument("campaign", type=Path)
    lab_verify_campaign.add_argument("--public-key", type=Path, required=True)
    lab_verify_campaign.add_argument("--image-manifest", type=Path, required=True)
    lab_verify_campaign.add_argument("--fixture-root", type=Path, required=True)
    lab_verify_campaign.add_argument("--attestation-dir", type=Path, required=True)
    lab_verify_campaign.add_argument("--minimum-runs", type=int, default=2)
    lab_profiles_cmd = lab_sub.add_parser("profiles")
    lab_plan = lab_sub.add_parser("plan")
    lab_plan.add_argument("--manifest", type=Path, required=True)
    lab_plan.add_argument("--output", type=Path, required=True)
    lab_build_provisioning = lab_sub.add_parser("build-provisioning-kit")
    lab_build_provisioning.add_argument("--source-root", type=Path, default=Path.cwd())
    lab_build_provisioning.add_argument("--output", type=Path, required=True)
    lab_build_provisioning.add_argument("--plan", type=Path)
    lab_build_provisioning.add_argument("--signing-private-key", type=Path)
    lab_build_provisioning.add_argument("--signing-public-key", type=Path)
    lab_verify_provisioning = lab_sub.add_parser("verify-provisioning-kit")
    lab_verify_provisioning.add_argument("package", type=Path)
    lab_verify_provisioning.add_argument("--public-key", type=Path)
    lab_provision = lab_sub.add_parser("provision")
    lab_provision.add_argument("--endpoint", type=Path, required=True)
    lab_provision.add_argument("--plan", type=Path, required=True)
    lab_provision.add_argument("--source-root", type=Path, default=Path.cwd())
    lab_provision.add_argument("--report-json", type=Path)
    lab_provision.add_argument("--timeout", type=int, default=7200)
    lab_binding = lab_sub.add_parser("release-binding")
    lab_binding.add_argument("--release-manifest", type=Path, required=True)
    lab_binding.add_argument("--artifact-dir", type=Path, required=True)
    lab_binding.add_argument("--release-public-key", type=Path, required=True)
    lab_binding.add_argument("--release-commit", required=True)
    lab_binding.add_argument("--output", type=Path, required=True)
    lab_matrix = lab_sub.add_parser("authoritative-matrix")
    lab_matrix.add_argument("--spec", type=Path, required=True)
    lab_matrix.add_argument("--output-dir", type=Path, required=True)
    lab_matrix.add_argument("--matrix-output", type=Path, required=True)
    lab_matrix.add_argument("--private-key", type=Path, required=True)
    lab_matrix.add_argument("--public-key", type=Path, required=True)
    lab_matrix.add_argument("--release-binding", type=Path, required=True)
    lab_matrix.add_argument("--timeout", type=int, default=1800)
    lab_verify_matrix = lab_sub.add_parser("verify-authoritative-matrix")
    lab_verify_matrix.add_argument("attestation", type=Path)
    lab_verify_matrix.add_argument("--public-key", type=Path, required=True)

    release = sub.add_parser("release", help="Build deterministic sources and signed release manifests")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_source = release_sub.add_parser("source")
    release_source.add_argument("--root", type=Path, default=Path.cwd())
    release_source.add_argument("--output-dir", type=Path, required=True)
    release_source.add_argument("--name", required=True)
    release_manifest = release_sub.add_parser("manifest")
    release_manifest.add_argument("artifact", type=Path, nargs="+")
    release_manifest.add_argument("--output", type=Path, required=True)
    release_manifest.add_argument("--signing-private-key", type=Path)
    release_manifest.add_argument("--signing-public-key", type=Path)
    release_verify = release_sub.add_parser("verify")
    release_verify.add_argument("manifest", type=Path)
    release_verify.add_argument("--artifact-dir", type=Path, required=True)
    release_verify.add_argument("--public-key", type=Path)
    release_repro = release_sub.add_parser("reproducible")
    release_repro.add_argument("first", type=Path)
    release_repro.add_argument("second", type=Path)

    worker = sub.add_parser("worker", help="Run or inspect an mTLS remote PowerShell worker")
    worker_sub = worker.add_subparsers(dest="worker_command", required=True)
    worker_serve = worker_sub.add_parser("serve")
    worker_serve.add_argument("--config", type=Path, required=True)
    worker_probe = worker_sub.add_parser("probe")
    worker_probe.add_argument("--config", type=Path, required=True)

    remote = sub.add_parser("remote", help="Submit signed jobs to a trusted remote worker")
    remote_sub = remote.add_subparsers(dest="remote_command", required=True)
    remote_probe = remote_sub.add_parser("probe")
    remote_probe.add_argument("--endpoint", type=Path, required=True)
    remote_probe.add_argument("--timeout", type=int, default=30)
    remote_test = remote_sub.add_parser("test")
    remote_test.add_argument("entrypoint", type=Path)
    remote_test.add_argument("--root", type=Path, default=Path.cwd())
    remote_test.add_argument("--include", type=Path, action="append", default=[])
    remote_test.add_argument("--endpoint", type=Path, required=True)
    remote_test.add_argument("--options", type=Path, help="JSON object forwarded to the worker harness")
    remote_test.add_argument("--report-json", type=Path)
    remote_test.add_argument("--timeout", type=int, default=1200)

    hybrid = sub.add_parser("hybrid", help="Run one signed Linux/Windows mixed matrix")
    hybrid_sub = hybrid.add_subparsers(dest="hybrid_command", required=True)
    hybrid_test = hybrid_sub.add_parser("test")
    hybrid_test.add_argument("entrypoint", type=Path)
    hybrid_test.add_argument("--root", type=Path, default=Path.cwd())
    hybrid_test.add_argument("--local-runtime", action="append", default=[])
    hybrid_test.add_argument("--local-arg", action="append", default=[])
    hybrid_test.add_argument("--worker-endpoint", type=Path, action="append", default=[])
    hybrid_test.add_argument("--include", type=Path, action="append", default=[])
    hybrid_test.add_argument("--remote-options", type=Path)
    hybrid_test.add_argument("--report-json", type=Path)
    hybrid_test.add_argument("--timeout", type=int, default=1200)

    full = sub.add_parser("full", help="Plan and execute the complete Linux/Windows runtime matrix")
    full_sub = full.add_subparsers(dest="full_command", required=True)
    full_init = full_sub.add_parser("init", help="Write the canonical complete-matrix specification template")
    full_init.add_argument("--output", type=Path, default=Path("psmatrix.full.json"))
    full_plan = full_sub.add_parser("plan", help="Inspect readiness of every declared local and remote target")
    full_plan.add_argument("--spec", type=Path, required=True)
    full_plan.add_argument("--output", type=Path)
    full_test = full_sub.add_parser("test", help="Run the complete mixed-platform matrix")
    full_test.add_argument("entrypoint", type=Path)
    full_test.add_argument("--spec", type=Path, required=True)
    full_test.add_argument("--root", type=Path, default=Path.cwd())
    full_test.add_argument("--include", type=Path, action="append", default=[])
    full_test.add_argument("--local-arg", action="append", default=[])
    full_test.add_argument("--remote-options", type=Path)
    full_test.add_argument("--timeout", type=int, default=1200)
    full_test.add_argument("--jobs", type=int, default=0)
    full_test.add_argument("--differential", choices=["off", "report", "strict"])
    full_test.add_argument("--report-json", type=Path)
    full_test.add_argument("--report-junit", type=Path)
    full_test.add_argument("--report-sarif", type=Path)
    full_test.add_argument("--report-html", type=Path)
    full_test.add_argument("--report-sbom", type=Path)
    full_test.add_argument("--evidence-bundle", type=Path)
    full_test.add_argument("--attestation", type=Path)
    full_test.add_argument("--signing-private-key", type=Path)
    full_test.add_argument("--signing-public-key", type=Path)
    full_test.add_argument("--builder-id")
    full_test.add_argument("--json", action="store_true")
    full_binding = full_sub.add_parser("release-binding", help="Bind the canonical 25-target matrix to a signed release")
    full_binding.add_argument("--release-manifest", type=Path, required=True)
    full_binding.add_argument("--artifact-dir", type=Path, required=True)
    full_binding.add_argument("--release-public-key", type=Path, required=True)
    full_binding.add_argument("--release-commit", required=True)
    full_binding.add_argument("--output", type=Path, required=True)
    full_attest = full_sub.add_parser("attest", help="Create release-bound canonical 25-target matrix evidence")
    full_attest.add_argument("--report", type=Path, required=True)
    full_attest.add_argument("--release-binding", type=Path, required=True)
    full_attest.add_argument("--private-key", type=Path, required=True)
    full_attest.add_argument("--public-key", type=Path, required=True)
    full_attest.add_argument("--output", type=Path, required=True)
    full_verify = full_sub.add_parser("verify-attestation", help="Verify release-bound canonical full-matrix evidence")
    full_verify.add_argument("--report", type=Path, required=True)
    full_verify.add_argument("--attestation", type=Path, required=True)
    full_verify.add_argument("--public-key", type=Path, required=True)

    adversarial = sub.add_parser("adversarial", help="Run the built-in defensive adversarial corpus")
    adversarial_sub = adversarial.add_subparsers(dest="adversarial_command", required=True)
    adversarial_sub.add_parser("list")
    adversarial_run = adversarial_sub.add_parser("run")
    adversarial_run.add_argument("--runtime", default="7.6.4")
    adversarial_run.add_argument("--strict", action="store_true")
    adversarial_run.add_argument("--category", action="append", default=[])
    adversarial_run.add_argument("--report-json", type=Path)
    adversarial_run.add_argument("--evidence-bundle", type=Path)

    recovery = sub.add_parser("recovery", help="Audit, repair, and chaos-test controller recovery state")
    recovery_sub = recovery.add_subparsers(dest="recovery_command", required=True)
    recovery_sub.add_parser("list", help="List bounded fault-injection recovery cases")
    recovery_run = recovery_sub.add_parser("run", help="Run the deterministic recovery campaign")
    recovery_run.add_argument("--report-json", type=Path)
    recovery_run.add_argument("--evidence-bundle", type=Path)
    recovery_run.add_argument("--attestation", type=Path)
    recovery_run.add_argument("--private-key", type=Path)
    recovery_run.add_argument("--public-key", type=Path)
    recovery_verify = recovery_sub.add_parser("verify-attestation")
    recovery_verify.add_argument("attestation", type=Path)
    recovery_verify.add_argument("--public-key", type=Path, required=True)
    journal = recovery_sub.add_parser("journal")
    journal.add_argument("path", type=Path)
    journal.add_argument("--repair", action="store_true")
    queue_inspect = recovery_sub.add_parser("queue-inspect")
    queue_inspect.add_argument("--queue", type=Path)
    queue_inspect.add_argument("--backup-root", type=Path)
    queue_inspect.add_argument("--full", action="store_true")
    queue_backup = recovery_sub.add_parser("queue-backup")
    queue_backup.add_argument("--queue", type=Path)
    queue_backup.add_argument("--backup-root", type=Path)
    queue_restore = recovery_sub.add_parser("queue-restore")
    queue_restore.add_argument("--queue", type=Path)
    queue_restore.add_argument("--backup-root", type=Path)
    queue_reconcile = recovery_sub.add_parser("queue-reconcile")
    queue_reconcile.add_argument("--queue", type=Path)
    transfer_audit = recovery_sub.add_parser("transfer-audit")
    transfer_audit.add_argument("--store", type=Path)
    transfer_audit.add_argument("--repair", action="store_true")

    mcp = sub.add_parser("mcp", help="Run the PSMatrix MCP server over stdio")
    mcp.add_argument("--root", type=Path, default=Path.cwd())

    mcp_http = sub.add_parser("mcp-http", help="Run or package the Streamable HTTP MCP service")
    mcp_http_sub = mcp_http.add_subparsers(dest="mcp_http_command", required=True)
    mcp_http_serve = mcp_http_sub.add_parser("serve", help="Run the bounded Streamable HTTP MCP server")
    mcp_http_serve.add_argument("--host", default="127.0.0.1")
    mcp_http_serve.add_argument("--port", type=int, default=8765)
    mcp_http_serve.add_argument("--endpoint", default="/mcp")
    mcp_http_serve.add_argument("--public-url")
    mcp_http_serve.add_argument("--auth-config", type=Path)
    mcp_http_serve.add_argument("--tls-cert", type=Path)
    mcp_http_serve.add_argument("--tls-key", type=Path)
    mcp_http_serve.add_argument("--client-ca", type=Path)
    mcp_http_serve.add_argument("--allowed-origin", action="append", default=[])
    mcp_http_serve.add_argument("--allowed-host", action="append", default=[])
    mcp_http_serve.add_argument("--max-message-bytes", type=int, default=4 * 1024 * 1024)
    mcp_http_serve.add_argument("--max-upload-bytes", type=int, default=128 * 1024 * 1024)
    mcp_http_serve.add_argument("--max-project-bytes", type=int, default=512 * 1024 * 1024)
    mcp_http_serve.add_argument("--max-files", type=int, default=256)
    mcp_http_serve.add_argument("--session-ttl", type=int, default=3600)
    mcp_http_serve.add_argument("--artifact-ttl", type=int, default=300)
    mcp_http_serve.add_argument("--rate-per-minute", type=int, default=120)
    mcp_http_serve.add_argument("--burst", type=int, default=30)
    mcp_http_serve.add_argument("--max-concurrent", type=int, default=4)
    mcp_http_serve.add_argument("--validation-workers", type=int, default=1)
    mcp_http_serve.add_argument("--openai-challenge-env", default="PSMATRIX_OPENAI_APPS_CHALLENGE")
    mcp_http_serve.add_argument("--disable-dashboard", action="store_true")
    mcp_http_serve.add_argument("--disable-metrics", action="store_true")
    mcp_http_serve.add_argument("--otlp-endpoint")
    mcp_http_serve.add_argument("--otlp-header", action="append", default=[], metavar="NAME=VALUE")
    mcp_http_serve.add_argument("--otlp-interval", type=int, default=60)
    mcp_http_bootstrap = mcp_http_sub.add_parser("build-bootstrap", help="Build a credential-free ChatGPT/Claude remote MCP bootstrap bundle")
    mcp_http_bootstrap.add_argument("--output", type=Path, required=True)
    mcp_http_bootstrap.add_argument("--public-url", required=True)
    mcp_http_bootstrap.add_argument("--auth-mode", choices=["oauth-introspection", "mtls", "hybrid"], default="oauth-introspection")

    ops = sub.add_parser("ops", help="Read operations state and build redacted support evidence")
    ops_sub = ops.add_subparsers(dest="ops_command", required=True)
    ops_snapshot = ops_sub.add_parser("snapshot")
    ops_snapshot.add_argument("--output", type=Path)
    ops_audit = ops_sub.add_parser("audit")
    ops_audit.add_argument("--action")
    ops_audit.add_argument("--query")
    ops_audit.add_argument("--session-id")
    ops_audit.add_argument("--since")
    ops_audit.add_argument("--limit", type=int, default=200)
    ops_reports = ops_sub.add_parser("reports")
    ops_reports.add_argument("--status")
    ops_reports.add_argument("--limit", type=int, default=200)
    ops_reports.add_argument("--root", type=Path)
    ops_metrics = ops_sub.add_parser("metrics")
    ops_metrics.add_argument("--output", type=Path)
    ops_support = ops_sub.add_parser("support-bundle")
    ops_support.add_argument("--output", type=Path, required=True)
    ops_certs = ops_sub.add_parser("certificates")
    ops_certs.add_argument("--warning-days", type=int, default=30)
    ops_otlp = ops_sub.add_parser("otlp-export")
    ops_otlp.add_argument("--endpoint", required=True)
    ops_otlp.add_argument("--header", action="append", default=[], metavar="NAME=VALUE")
    ops_otlp.add_argument("--timeout", type=int, default=10)

    ga = sub.add_parser("ga", help="Evaluate and attest the fail-closed Production GA gate")
    ga_sub = ga.add_subparsers(dest="ga_command", required=True)
    ga_init = ga_sub.add_parser("init", help="Write the mandatory 2.0.0 GA policy template")
    ga_init.add_argument("--output", type=Path, required=True)
    ga_evaluate = ga_sub.add_parser("evaluate", help="Evaluate every mandatory GA evidence gate")
    ga_evaluate.add_argument("--policy", type=Path, required=True)
    ga_evaluate.add_argument("--output", type=Path)
    ga_proof_create = ga_sub.add_parser("proof-create", help="Sign a normalized external GA proof result")
    ga_proof_create.add_argument("--type", required=True, choices=["public-oauth", "public-mtls", "external-otlp", "key-rotation", "security-review", "vulnerability-scan"])
    ga_proof_create.add_argument("--input", type=Path, required=True)
    ga_proof_create.add_argument("--private-key", type=Path, required=True)
    ga_proof_create.add_argument("--public-key", type=Path, required=True)
    ga_proof_create.add_argument("--output", type=Path, required=True)
    ga_proof_verify = ga_sub.add_parser("proof-verify", help="Verify a signed external GA proof")
    ga_proof_verify.add_argument("--type", required=True, choices=["public-oauth", "public-mtls", "external-otlp", "key-rotation", "security-review", "vulnerability-scan"])
    ga_proof_verify.add_argument("--attestation", type=Path, required=True)
    ga_proof_verify.add_argument("--public-key", type=Path, required=True)
    ga_review_packet = ga_sub.add_parser("review-packet", help="Build a deterministic independent security-review dossier")
    ga_review_packet.add_argument("--root", type=Path, default=Path.cwd())
    ga_review_packet.add_argument("--source-archive", type=Path, required=True)
    ga_review_packet.add_argument("--release-manifest", type=Path, required=True)
    ga_review_packet.add_argument("--output", type=Path, required=True)
    ga_review_finalize = ga_sub.add_parser("review-finalize", help="Validate and sign a completed independent security review")
    ga_review_finalize.add_argument("--report", type=Path, required=True)
    ga_review_finalize.add_argument("--source-archive", type=Path, required=True)
    ga_review_finalize.add_argument("--release-manifest", type=Path, required=True)
    ga_review_finalize.add_argument("--private-key", type=Path, required=True)
    ga_review_finalize.add_argument("--public-key", type=Path, required=True)
    ga_review_finalize.add_argument("--result-output", type=Path, required=True)
    ga_review_finalize.add_argument("--attestation-output", type=Path, required=True)
    ga_artifact_sign = ga_sub.add_parser("artifact-sign", help="Sign a CI validation or full-matrix artifact digest")
    ga_artifact_sign.add_argument("--type", required=True, choices=["validation-summary", "full-matrix-report"])
    ga_artifact_sign.add_argument("--artifact", type=Path, required=True)
    ga_artifact_sign.add_argument("--observed-at", required=True)
    ga_artifact_sign.add_argument("--private-key", type=Path, required=True)
    ga_artifact_sign.add_argument("--public-key", type=Path, required=True)
    ga_artifact_sign.add_argument("--output", type=Path, required=True)
    ga_artifact_verify = ga_sub.add_parser("artifact-verify", help="Verify CI-signed GA artifact digest binding")
    ga_artifact_verify.add_argument("--type", required=True, choices=["validation-summary", "full-matrix-report"])
    ga_artifact_verify.add_argument("--artifact", type=Path, required=True)
    ga_artifact_verify.add_argument("--attestation", type=Path, required=True)
    ga_artifact_verify.add_argument("--public-key", type=Path, required=True)
    ga_rotation = ga_sub.add_parser("key-rotation-drill", help="Run and sign an isolated rotation/revocation drill")
    ga_rotation.add_argument("--private-key", type=Path, required=True)
    ga_rotation.add_argument("--public-key", type=Path, required=True)
    ga_rotation.add_argument("--output", type=Path, required=True)
    ga_sign = ga_sub.add_parser("sign", help="Re-evaluate the policy and create final GA attestation only on PASS")
    ga_sign.add_argument("--policy", type=Path, required=True)
    ga_sign.add_argument("--evaluation-output", type=Path)
    ga_sign.add_argument("--private-key", type=Path, required=True)
    ga_sign.add_argument("--public-key", type=Path, required=True)
    ga_sign.add_argument("--output", type=Path, required=True)
    ga_verify = ga_sub.add_parser("verify", help="Verify final 2.0.0 Production GA attestation")
    ga_verify.add_argument("--attestation", type=Path, required=True)
    ga_verify.add_argument("--public-key", type=Path, required=True)

    sub.add_parser("channels", help="Show built-in runtime channels")
    return parser


def cmd_doctor(manager: RuntimeManager, modules: ModuleManager, oci: OciRuntimeManager) -> int:
    payload = {
        "psmatrix_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "arch": normalize_arch(),
        "host_abi": detect_host_abi(),
        "home": str(manager.home),
        "system_pwsh": shutil.which("pwsh"),
        "installed_runtimes": manager.list_installed(),
        "installed_oci_runtimes": oci.list_installed(),
        "container_engines": detect_container_engines(),
        "installed_modules": modules.list_installed(),
        "result_cache": ResultCache(manager.home / "result-cache").stats(),
        "sandbox": detect_capabilities().to_dict(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _plan_target(
    manager: RuntimeManager,
    oci: OciRuntimeManager,
    spec,
    *,
    backend: str,
    engine: str,
) -> dict[str, object]:
    native = manager.plan(spec)
    if backend == "native":
        return {"selected_backend": "native", "native": native, **native}
    oci_plan = oci.plan(spec, engine=engine)
    if backend == "oci":
        return {"selected_backend": "oci", "oci": oci_plan, **oci_plan}
    if native.get("status") == "READY":
        return {"selected_backend": "native", "native": native, "oci": oci_plan, **native}
    if oci_plan.get("status") == "READY":
        return {"selected_backend": "oci", "native": native, "oci": oci_plan, **oci_plan}
    legacy = bool(release_metadata(spec.version).get("legacy_host"))
    selected = "oci" if legacy else "native"
    selected_plan = oci_plan if selected == "oci" else native
    return {
        "selected_backend": selected,
        "native": native,
        "oci": oci_plan,
        **selected_plan,
    }


def _install_target(
    manager: RuntimeManager,
    oci: OciRuntimeManager,
    spec,
    *,
    backend: str,
    engine: str,
    force: bool = False,
) -> dict[str, object]:
    if backend not in {"auto", "native", "oci"}:
        raise ValueError(f"Unsupported runtime backend: {backend}")
    legacy = bool(release_metadata(spec.version).get("legacy_host"))
    order = [backend] if backend != "auto" else (["oci", "native"] if legacy else ["native", "oci"])
    failures: list[str] = []
    for selected in order:
        try:
            if selected == "oci":
                payload = oci.install(spec, engine=engine, force=force)
                return {
                    "runtime_id": spec.runtime_id,
                    "backend": "oci",
                    "status": "INSTALLED",
                    "image": payload.get("image_pinned"),
                    "repo_digest": payload.get("repo_digest"),
                }
            installation = manager.install(spec, force=force)
            return {
                "runtime_id": spec.runtime_id,
                "backend": "native",
                "status": "INSTALLED",
                "path": str(installation.executable),
                "sha256": installation.sha256,
            }
        except (PSMatrixError, OSError, ValueError) as exc:
            failures.append(f"{selected}: {exc}")
    raise PSMatrixError(
        f"No install backend succeeded for {spec.runtime_id} (" + "; ".join(failures) + ")"
    )


def cmd_test(args, manager: RuntimeManager, modules: ModuleManager) -> int:
    if args.coverage_fail_under is not None and not 0 <= args.coverage_fail_under <= 100:
        raise PSMatrixError("--coverage-fail-under must be between 0 and 100")
    files: list[Path] = []
    for path in args.paths:
        files.extend(scan_powershell_files(path))
    files = sorted(set(path.resolve() for path in files))
    if not files:
        raise PSMatrixError("No .ps1, .psm1, or .psd1 files found")

    versions = list(args.runtime)
    if args.matrix:
        versions.extend(matrix_versions(args.matrix))
    if not versions:
        versions = [BUILTIN_CHANNELS["stable"].version]
    versions = list(dict.fromkeys(versions))

    arch = args.arch or normalize_arch()
    specs = [resolve_runtime(version, arch, args.libc) for version in versions]
    install_failures: dict[str, str] = {}
    oci = OciRuntimeManager(manager.home)
    if args.install_missing:
        for spec in specs:
            try:
                _install_target(
                    manager, oci, spec,
                    backend=args.backend, engine=args.container_engine,
                )
            except (PSMatrixError, OSError, ValueError) as exc:
                install_failures[spec.runtime_id] = str(exc)

    environment_values = list(args.env)
    for env_file in args.env_file:
        environment_values.extend(_load_env_file(env_file))
    environment = _parse_string_assignments(environment_values, label="--env")

    string_parameters = _parse_string_assignments(args.param, label="--param")
    json_parameters = _parse_json_assignments(args.param_json)
    parameter_names = {name.casefold() for name, _ in string_parameters}
    duplicates = sorted(name for name, _ in json_parameters if name.casefold() in parameter_names)
    if duplicates:
        raise PSMatrixError("Parameters assigned by both --param and --param-json: " + ", ".join(duplicates))
    parameters: tuple[tuple[str, object], ...] = tuple(string_parameters) + tuple(json_parameters)

    stdin_data = None
    stdin_source = None
    if args.stdin_text is not None:
        stdin_data = args.stdin_text.encode("utf-8")
        stdin_source = "cli:text"
    elif args.stdin_file is not None:
        stdin_path = args.stdin_file.resolve()
        if not stdin_path.is_file():
            raise PSMatrixError(f"stdin file not found: {stdin_path}")
        stdin_data = stdin_path.read_bytes()
        stdin_source = str(stdin_path)

    package_root = Path(__file__).resolve().parent
    runner = ScriptRunner(manager, modules, package_root)
    options = RunOptions(
        timeout_seconds=args.timeout,
        max_output_bytes=args.max_output_mib * 1024 * 1024,
        sandbox=args.sandbox,
        keep_sandbox=args.keep_sandbox,
        network=args.network,
        max_file_bytes=args.max_file_mib * 1024 * 1024,
        max_workspace_bytes=args.max_workspace_mib * 1024 * 1024,
        max_memory_bytes=args.max_memory_mib * 1024 * 1024,
        max_committed_memory_bytes=(
            args.max_committed_memory_mib * 1024 * 1024
            if args.max_committed_memory_mib is not None
            else None
        ),
        max_processes=args.max_processes,
        max_open_files=args.max_open_files,
        psscriptanalyzer=args.psscriptanalyzer,
        analyzer_fail_on=args.analyzer_fail_on,
        pester=args.pester,
        coverage=args.coverage,
        coverage_fail_under=args.coverage_fail_under,
        native_exit_policy=args.native_exit,
        stream_error_policy=args.stream_errors,
        runtime_backend=args.backend,
        container_engine=args.container_engine,
        arguments=tuple(args.arg),
        parameters=parameters,
        environment=environment,
        stdin_data=stdin_data,
        stdin_source=stdin_source,
        fixtures=_parse_fixture_values(args.fixture),
        setup_scripts=tuple(args.setup),
        teardown_scripts=tuple(args.teardown),
        dependency_lockfile=str(args.lockfile.resolve()) if args.lockfile else None,
        dependency_policy=args.dependencies,
    )
    signing_values = [args.attestation, args.signing_private_key, args.signing_public_key, args.builder_id]
    if any(value is not None for value in signing_values):
        if not all(value is not None for value in signing_values) or args.evidence_bundle is None:
            raise PSMatrixError("Signed provenance requires --evidence-bundle, --attestation, --signing-private-key, --signing-public-key, and --builder-id")
    if args.jobs < 0:
        raise PSMatrixError("--jobs cannot be negative")
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        raise PSMatrixError("shard values must satisfy count >= 1 and 0 <= index < count")
    if args.resume and args.checkpoint and args.resume.resolve() != args.checkpoint.resolve():
        raise PSMatrixError("--resume and --checkpoint must reference the same file when both are supplied")

    started = utc_now_iso()
    cache_root = (args.cache_dir or (manager.home / "result-cache")).resolve()
    result_cache = ResultCache(cache_root) if args.cache != "off" else None
    checkpoint_path = args.resume or args.checkpoint
    checkpoint = CheckpointStore(checkpoint_path)
    jobs = build_jobs(
        files, specs, options,
        tool_version=__version__,
        runtime_manager=manager,
        oci_manager=oci,
        tool_modules=installed_modules_fingerprint(modules.list_installed()),
        engine=engine_fingerprint(package_root),
        shard_index=args.shard_index,
        shard_count=args.shard_count,
    )
    scheduled = execute_jobs(
        jobs,
        lambda path, spec: runner.run(path, spec, options),
        cache=result_cache,
        cache_mode=args.cache,
        checkpoint=checkpoint,
        resume=args.resume is not None,
        jobs_count=args.jobs,
        fail_fast=args.fail_fast,
        per_worker_memory_bytes=options.max_memory_bytes,
        worker_payload_factory=lambda job: {
            "home": str(manager.home),
            "package_root": str(package_root),
            "source": str(job.source),
            "spec": asdict(job.spec),
            "options": asdict(options),
        },
    )
    targets = scheduled.targets
    differential_mode = args.differential
    if differential_mode == "auto":
        differential_mode = "report" if len(specs) > 1 else "off"
    differential = (
        compare_targets(targets, baseline_runtime=args.baseline_runtime)
        if differential_mode != "off"
        else []
    )
    has_differences = any(item.get("issue_count", 0) for item in differential)
    statuses = {target.status for target in targets}
    hard_failures = statuses - {"PASS", "UNTESTED_RUNTIME"}
    if hard_failures:
        status = "FAIL"
    elif "UNTESTED_RUNTIME" in statuses:
        status = "INCOMPLETE"
    elif has_differences and differential_mode == "strict":
        status = "FAIL_DIFFERENTIAL"
    elif has_differences:
        status = "PASS_WITH_DIFFERENCES"
    else:
        status = "PASS"
    finished = utc_now_iso()
    diagnostics = collect_diagnostics(targets)
    report = MatrixReport(
        schema=6,
        tool_version=__version__,
        started_at=started,
        finished_at=finished,
        status=status,
        targets=targets,
        differential=differential,
        diagnostics=diagnostics,
        matrix={
            "versions": versions,
            "runtime_ids": [spec.runtime_id for spec in specs],
            "arch": arch,
            "libc": args.libc,
            "backend": args.backend,
            "container_engine": args.container_engine,
            "differential_mode": differential_mode,
            "baseline_runtime": args.baseline_runtime,
            "install_failures": install_failures,
            "scheduler": scheduled.metadata,
            "shard": {"index": args.shard_index, "count": args.shard_count, "selected_jobs": len(jobs)},
            "cache": {
                "mode": args.cache,
                "directory": str(cache_root) if result_cache is not None else None,
                "stats": result_cache.stats() if result_cache is not None else None,
            },
            "checkpoint": str(checkpoint_path.resolve()) if checkpoint_path else None,
            "input_configuration": {
                "arguments": len(args.arg),
                "parameter_names": sorted(name for name, _ in parameters),
                "environment_names": sorted(name for name, _ in environment),
                "stdin_present": stdin_data is not None,
                "fixture_count": len(args.fixture),
                "setup_count": len(args.setup),
                "teardown_count": len(args.teardown),
                "dependency_policy": args.dependencies,
                "lockfile": str(args.lockfile.resolve()) if args.lockfile else None,
                "coverage_policy": args.coverage,
                "coverage_fail_under": args.coverage_fail_under,
                "native_exit_policy": args.native_exit,
                "stream_error_policy": args.stream_errors,
            },
        },
    )
    if args.report_json:
        atomic_write_json(args.report_json.resolve(), report.to_dict())
    if args.report_junit:
        write_junit(report, args.report_junit)
    if args.report_sarif:
        write_sarif(report, args.report_sarif)
    if args.report_html:
        write_html(report, args.report_html)
    if args.report_sbom:
        write_sbom(report, args.report_sbom)
    if args.evidence_bundle:
        common_root = Path(os.path.commonpath([str(path.parent) for path in files])) if files else Path.cwd()
        write_evidence_bundle(report, args.evidence_bundle, project_root=common_root)
        if args.attestation is not None:
            statement = build_slsa_provenance(
                artifact=args.evidence_bundle, report=report.to_dict(), builder_id=args.builder_id,
            )
            envelope = sign_provenance(statement, args.signing_private_key, args.signing_public_key)
            write_attestation(args.attestation, envelope)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_human(report), end="")
    return 0 if status in {"PASS", "PASS_WITH_DIFFERENCES"} else 1



def _validation_argv(values: list[str], file_path: Path | None) -> list[str]:
    result = list(values)
    if file_path is not None:
        payload = json.loads(file_path.resolve().read_text(encoding="utf-8"))
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise PSMatrixError("Validation file must contain a JSON array of strings")
        if result:
            raise PSMatrixError("Use either --validation-arg or --validation-file, not both")
        result = payload
    if not result:
        raise PSMatrixError("Validation arguments are required")
    return result


def _root_output(root: Path, value: Path) -> Path:
    root = root.resolve()
    candidate = value if value.is_absolute() else root / value
    resolved = candidate.resolve()
    try:
        if os.path.commonpath([str(root), str(resolved)]) != str(root):
            raise PSMatrixError(f"Output path escapes project root: {value}")
    except ValueError as exc:
        raise PSMatrixError(f"Output path escapes project root: {value}") from exc
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    manager = RuntimeManager(args.home)
    modules = ModuleManager(args.home)
    oci = OciRuntimeManager(args.home)
    try:
        if args.command == "doctor":
            return cmd_doctor(manager, modules, oci)
        if args.command == "cache":
            cache_root = (args.cache_dir or (manager.home / "result-cache")).resolve()
            result_cache = ResultCache(cache_root)
            if args.cache_command == "stats":
                print(json.dumps({"directory": str(cache_root), **result_cache.stats()}, indent=2))
                return 0
            if args.cache_command == "clear":
                removed = result_cache.clear()
                print(json.dumps({"directory": str(cache_root), "removed": removed, **result_cache.stats()}, indent=2))
                return 0
            if args.cache_command == "prune":
                if args.max_age_days is None and args.max_records is None:
                    raise PSMatrixError("cache prune requires --max-age-days or --max-records")
                if args.max_age_days is not None and args.max_age_days < 0:
                    raise PSMatrixError("--max-age-days cannot be negative")
                if args.max_records is not None and args.max_records < 0:
                    raise PSMatrixError("--max-records cannot be negative")
                payload = result_cache.prune(
                    max_age_days=args.max_age_days, max_records=args.max_records
                )
                print(json.dumps({"directory": str(cache_root), **payload}, indent=2))
                return 0
        if args.command == "plan":
            arch = getattr(args, "arch", None) or normalize_arch()
            versions = list(args.runtime) or matrix_versions(args.matrix)
            specs = [resolve_runtime(version, arch, args.libc) for version in versions]
            payload = {
                "matrix": args.matrix if not args.runtime else "custom",
                "arch": arch,
                "libc": args.libc,
                "host_abi": detect_host_abi(),
                "backend": args.backend,
                "container_engine": args.container_engine,
                "targets": [
                    {
                        **_plan_target(
                            manager, oci, spec,
                            backend=args.backend, engine=args.container_engine,
                        ),
                        **release_metadata(spec.version),
                    }
                    for spec in specs
                ],
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            ready = all(item["status"] == "READY" for item in payload["targets"])
            return 0 if ready else 1
        if args.command == "diagnose":
            payload = json.loads(args.report.resolve().read_text(encoding="utf-8"))
            diagnostics, summary = report_diagnostics(payload)
            result = {"summary": summary, "diagnostics": diagnostics}
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Diagnostics: {summary['count']} (repairable: {summary['repairable_count']})")
                for item in diagnostics:
                    location = f":{item.get('line')}:{item.get('column') or 1}" if item.get('line') else ""
                    print(f"[{item.get('severity')}] {item.get('code')} {item.get('source')}{location} — {item.get('message')}")
            return 0 if not diagnostics else 1
        if args.command == "repair":
            root = args.root.resolve()
            if args.repair_command == "plan":
                report = json.loads(args.report.resolve().read_text(encoding="utf-8"))
                validation = _validation_argv(args.validation_arg, args.validation_file)
                plan = build_repair_plan(report, root, validation_argv=validation)
                output = _root_output(root, args.output)
                atomic_write_json(output, plan)
                print(json.dumps({"output": str(output), "plan_id": plan["plan_id"], "sources": len(plan["sources"]), "diagnostics": plan["diagnostic_summary"]}, ensure_ascii=False, indent=2))
                return 0
            if args.repair_command == "propose":
                proposal = json.loads(args.proposal.resolve().read_text(encoding="utf-8"))
                plan = json.loads(args.plan.resolve().read_text(encoding="utf-8"))
                bundle = propose_patch(root, proposal, plan=plan)
                output = _root_output(root, args.output)
                atomic_write_json(output, bundle)
                print(json.dumps({"output": str(output), "bundle_id": bundle["bundle_id"], "summary": bundle["summary"]}, ensure_ascii=False, indent=2))
                return 0
            if args.repair_command == "apply":
                bundle = json.loads(args.bundle.resolve().read_text(encoding="utf-8"))
                validation = _validation_argv(args.validation_arg, args.validation_file)
                session = _root_output(root, args.session)
                result = apply_and_validate(root, manager.home, bundle, validation, session_path=session, max_attempts=args.max_attempts)
                receipt_path = None
                if result["accepted"]:
                    receipt = create_gate_receipt(result["report"], root, manager.home, transaction_id=result["attempt"].get("transaction_id"))
                    receipt_path = _root_output(root, args.receipt)
                    write_gate_receipt(receipt_path, receipt)
                payload = {"accepted": result["accepted"], "attempt": result["attempt"], "session": str(session), "receipt": str(receipt_path) if receipt_path else None}
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0 if result["accepted"] else 1
        if args.command == "gate":
            if args.gate_command == "issue":
                root = args.root.resolve()
                report = json.loads(args.report.resolve().read_text(encoding="utf-8"))
                receipt = create_gate_receipt(report, root, manager.home)
                output = _root_output(root, args.output)
                write_gate_receipt(output, receipt)
                print(json.dumps({"output": str(output), "report_status": receipt["report_status"], "sources": len(receipt["sources"]), "signature": receipt["signature"]["algorithm"]}, ensure_ascii=False, indent=2))
                return 0
            if args.gate_command == "verify":
                result = verify_gate_receipt(load_gate_receipt(args.receipt.resolve()), args.root.resolve(), manager.home)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["valid"] else 1
        if args.command == "trust":
            store = TrustStore(manager.home)
            if args.trust_command == "keygen":
                payload = generate_ed25519_keypair(args.private_key, args.public_key, force=args.force)
                print(json.dumps({**payload, "private_key": str(args.private_key.resolve()), "public_key": str(args.public_key.resolve())}, ensure_ascii=False, indent=2))
                return 0
            if args.trust_command == "add":
                trusted = store.add(args.identity, args.role, args.public_key, certificate=args.certificate, replace=args.replace)
                print(json.dumps({"identity": trusted.identity, "role": trusted.role, "key_id": trusted.key_id, "public_key": str(trusted.public_key), "certificate_sha256": trusted.certificate_sha256}, ensure_ascii=False, indent=2))
                return 0
            if args.trust_command == "rotate":
                trusted = store.rotate(args.identity, args.role, args.public_key, certificate=args.certificate, expected_current_key_id=args.expected_current_key_id)
                print(json.dumps({"identity": trusted.identity, "role": trusted.role, "key_id": trusted.key_id, "public_key": str(trusted.public_key), "certificate_sha256": trusted.certificate_sha256}, ensure_ascii=False, indent=2))
                return 0
            if args.trust_command == "revoke":
                print(json.dumps(store.revoke(args.identity, args.role, reason=args.reason), ensure_ascii=False, indent=2))
                return 0
            if args.trust_command == "list":
                print(json.dumps({"entries": store.list()}, ensure_ascii=False, indent=2))
                return 0
        if args.command == "attest":
            if args.attest_command == "create":
                report = json.loads(args.report.resolve().read_text(encoding="utf-8"))
                statement = build_slsa_provenance(artifact=args.artifact, report=report, builder_id=args.builder_id, worker_identity=args.worker_identity)
                envelope = sign_provenance(statement, args.private_key, args.public_key)
                write_attestation(args.output, envelope)
                print(json.dumps({"output": str(args.output.resolve()), "subject": statement["subject"], "builder_id": args.builder_id, "signature_count": len(envelope["signatures"])}, ensure_ascii=False, indent=2))
                return 0
            if args.attest_command == "verify":
                result = verify_provenance(load_attestation(args.attestation), args.public_key, artifact=args.artifact)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "pki":
            if args.pki_command == "create-ca":
                print(json.dumps(create_ca(args.output, common_name=args.common_name, days=args.days, force=args.force), ensure_ascii=False, indent=2))
                return 0
            if args.pki_command == "issue":
                print(json.dumps(issue_certificate(args.ca_certificate, args.ca_private_key, args.output, common_name=args.common_name, role=args.role, dns_names=list(args.dns_name), days=args.days, force=args.force), ensure_ascii=False, indent=2))
                return 0
            if args.pki_command == "inspect":
                print(json.dumps(inspect_certificate(args.certificate), ensure_ascii=False, indent=2))
                return 0
            if args.pki_command == "create-rotation":
                result = create_rotation_bundle(args.output, identity=args.identity, role=args.role, certificate=args.certificate, private_key=args.private_key, ca_certificate=args.ca_certificate, signing_private_key=args.signing_private_key, signing_public_key=args.signing_public_key, generation=args.generation)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.pki_command == "apply-rotation":
                result = apply_rotation_bundle(args.bundle, args.destination, signing_public_key=args.public_key, expected_identity=args.identity, expected_role=args.role, minimum_days_remaining=args.minimum_days)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "snapshot":
            if args.snapshot_command == "restore":
                envelope = SnapshotAdapter(SnapshotAdapterConfig.load(args.config)).restore(phase=args.phase, private_key=args.private_key, public_key=args.public_key)
                if args.output is not None:
                    atomic_write_json(args.output.resolve(), envelope)
                print(json.dumps(envelope, ensure_ascii=False, indent=2))
                return 0
            if args.snapshot_command == "verify":
                envelope = json.loads(args.attestation.resolve().read_text(encoding="utf-8"))
                result = verify_snapshot_attestation(envelope, args.public_key, worker_id=args.worker_id, vm_id=args.vm_id, snapshot_id=args.snapshot_id, phase=args.phase)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "fleet":
            registry = FleetRegistry(manager.home)
            if args.fleet_command == "enroll":
                labels = dict(_parse_string_assignments(args.label, label="--label"))
                result = registry.enroll(args.endpoint, labels=labels, priority=args.priority, replace=args.replace, snapshot_config=args.snapshot_config, reset_private_key=args.reset_private_key, reset_public_key=args.reset_public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.fleet_command == "list":
                print(json.dumps({"workers": registry.list(include_revoked=args.all)}, ensure_ascii=False, indent=2))
                return 0
            if args.fleet_command == "health":
                result = probe_fleet_worker(registry, args.worker_id, timeout=args.timeout, quarantine_threshold=args.quarantine_threshold)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.fleet_command in {"quarantine", "activate", "revoke"}:
                target_state = {"quarantine": "QUARANTINED", "activate": "ACTIVE", "revoke": "REVOKED"}[args.fleet_command]
                print(json.dumps(registry.transition(args.worker_id, target_state, reason=args.reason), ensure_ascii=False, indent=2))
                return 0
            if args.fleet_command == "select":
                labels = dict(_parse_string_assignments(args.label, label="--label"))
                selected = registry.select(args.runtime_id, labels=labels, count=args.count, require_healthy=not args.allow_unprobed)
                print(json.dumps({"workers": [item.to_dict() for item in selected]}, ensure_ascii=False, indent=2))
                return 0 if selected else 1
            if args.fleet_command.startswith("queue-"):
                queue = FleetQueue(manager.home / "fleet" / "queue.sqlite3")
                if args.fleet_command == "queue-run":
                    recovery_journal = RecoveryJournal(
                        (args.recovery_journal or (manager.home / "fleet" / "controller-recovery.jsonl")).resolve()
                    )
                    result = serve_queue(
                        registry,
                        queue,
                        owner=args.owner,
                        runtime_ids=list(args.runtime_id),
                        lease_seconds=args.lease_seconds,
                        timeout=args.timeout,
                        quarantine_threshold=args.quarantine_threshold,
                        poll_seconds=args.poll_seconds,
                        max_jobs=args.max_jobs,
                        recovery_journal=recovery_journal,
                    )
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 0 if result.get("failed") == 0 else 1
                if args.fleet_command == "queue-enqueue":
                    payload = json.loads(args.payload.resolve().read_text(encoding="utf-8"))
                    if not isinstance(payload, dict):
                        raise PSMatrixError("Fleet queue payload root must be an object")
                    result = queue.enqueue(runtime_id=args.runtime_id, payload=payload, idempotency_key=args.idempotency_key, priority=args.priority, max_attempts=args.max_attempts)
                elif args.fleet_command == "queue-claim":
                    result = queue.claim(owner=args.owner, runtime_ids=list(args.runtime_id), lease_seconds=args.lease_seconds)
                elif args.fleet_command == "queue-heartbeat":
                    result = queue.heartbeat(args.job_id, owner=args.owner, lease_seconds=args.lease_seconds)
                elif args.fleet_command == "queue-complete":
                    value = json.loads(args.result.resolve().read_text(encoding="utf-8"))
                    if not isinstance(value, dict):
                        raise PSMatrixError("Fleet queue result root must be an object")
                    result = queue.complete(args.job_id, owner=args.owner, result=value)
                elif args.fleet_command == "queue-fail":
                    result = queue.fail(args.job_id, owner=args.owner, error=args.error, retry=not args.no_retry)
                else:
                    result = {"jobs": queue.list(state=args.state, limit=args.limit)}
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.fleet_command == "test":
                worker_id = args.worker_id
                if not worker_id:
                    if not args.runtime_id:
                        raise PSMatrixError("fleet test requires --worker-id or --runtime-id")
                    labels = dict(_parse_string_assignments(args.label, label="--label"))
                    selected = registry.select(args.runtime_id, labels=labels, count=1, require_healthy=True)
                    if not selected:
                        raise PSMatrixError("No healthy fleet worker matches the requested runtime and labels")
                    worker_id = selected[0].worker_id
                root = args.root.resolve()
                entrypoint = args.entrypoint.resolve()
                options = {}
                if args.options is not None:
                    options = json.loads(args.options.resolve().read_text(encoding="utf-8"))
                    if not isinstance(options, dict):
                        raise PSMatrixError("Fleet worker options root must be an object")
                result = execute_managed_fleet_job(registry, worker_id=worker_id, root=root, files=[entrypoint, *(item.resolve() for item in args.include)], entrypoint=entrypoint, options=options, timeout=args.timeout)
                if args.report_json is not None:
                    atomic_write_json(args.report_json.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("status") == "PASS" else 1
        if args.command == "deploy":
            if args.deploy_command == "windows-package":
                result = build_windows_worker_package(args.source_root, args.output, version=__version__, wheel=args.wheel, signing_private_key=args.signing_private_key, signing_public_key=args.signing_public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.deploy_command == "verify":
                result = verify_windows_worker_package(args.package, signing_public_key=args.public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "lab":
            if args.lab_command == "build-kit":
                result = build_certification_kit(
                    args.source_root, args.output, version=__version__,
                    signing_private_key=args.signing_private_key,
                    signing_public_key=args.signing_public_key,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "verify-kit":
                result = verify_certification_kit(args.package, signing_public_key=args.public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "certify":
                endpoint = RemoteEndpoint.load(args.endpoint, trust_home=manager.home)
                result = certify_remote_windows_image(
                    endpoint=endpoint, image_manifest=args.image_manifest, fixture_root=args.fixture_root,
                    output=args.output, private_key=args.private_key, public_key=args.public_key, timeout=args.timeout,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "verify-certification":
                result = verify_certification_attestation(
                    args.attestation, public_key=args.public_key, image_manifest=args.image_manifest,
                    fixture_root=args.fixture_root,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "campaign":
                endpoint = RemoteEndpoint.load(args.endpoint, trust_home=manager.home)
                result = run_certification_campaign(
                    endpoint=endpoint, image_manifest=args.image_manifest, fixture_root=args.fixture_root,
                    output_dir=args.output_dir, campaign_output=args.campaign_output,
                    private_key=args.private_key, public_key=args.public_key, campaign_id=args.campaign_id,
                    iterations=args.iterations, timeout=args.timeout,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "verify-campaign":
                result = verify_campaign_attestation(
                    args.campaign, public_key=args.public_key, image_manifest=args.image_manifest,
                    fixture_root=args.fixture_root, attestation_dir=args.attestation_dir,
                    minimum_runs=args.minimum_runs,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "profiles":
                print(json.dumps(lab_profiles(), ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "plan":
                result = build_provision_plan(args.manifest, output=args.output)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "build-provisioning-kit":
                result = build_provisioning_kit(
                    args.source_root, args.output, version=__version__, plan_path=args.plan,
                    signing_private_key=args.signing_private_key, signing_public_key=args.signing_public_key,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "verify-provisioning-kit":
                result = verify_provisioning_kit(args.package, signing_public_key=args.public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "provision":
                endpoint = RemoteEndpoint.load(args.endpoint, trust_home=manager.home)
                result = provision_remote_hyperv_lab(
                    endpoint, plan_path=args.plan, source_root=args.source_root, timeout=args.timeout,
                )
                if args.report_json is not None:
                    atomic_write_json(args.report_json.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("status") == "PASS" else 1
            if args.lab_command == "release-binding":
                result = build_windows_release_binding(
                    release_manifest=args.release_manifest, artifact_dir=args.artifact_dir,
                    release_public_key=args.release_public_key, release_commit=args.release_commit,
                    output=args.output,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.lab_command == "authoritative-matrix":
                result = run_authoritative_matrix(
                    args.spec, output_dir=args.output_dir, matrix_output=args.matrix_output,
                    private_key=args.private_key, public_key=args.public_key,
                    trust_home=manager.home, release_binding_path=args.release_binding, timeout=args.timeout,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("status") == "PASS" else 1
            if args.lab_command == "verify-authoritative-matrix":
                result = verify_authoritative_matrix_attestation(args.attestation, public_key=args.public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "release":
            if args.release_command == "source":
                print(json.dumps(build_reproducible_source(args.root, args.output_dir, name=args.name), ensure_ascii=False, indent=2))
                return 0
            if args.release_command == "manifest":
                print(json.dumps(create_release_manifest(args.artifact, args.output, version=__version__, signing_private_key=args.signing_private_key, signing_public_key=args.signing_public_key), ensure_ascii=False, indent=2))
                return 0
            if args.release_command == "verify":
                print(json.dumps(verify_release_manifest(args.manifest, args.artifact_dir, signing_public_key=args.public_key), ensure_ascii=False, indent=2))
                return 0
            if args.release_command == "reproducible":
                print(json.dumps(verify_reproducible_build(args.first, args.second), ensure_ascii=False, indent=2))
                return 0
        if args.command == "worker":
            config = WorkerConfig.load(args.config)
            harness = Path(__file__).resolve().parents[2] / "workers" / "windows" / "worker_harness.ps1"
            if not harness.is_file():
                packaged = Path(__file__).resolve().with_name("windows_worker.ps1")
                harness = packaged
            if args.worker_command == "probe":
                executor = WindowsJobExecutor(config, harness)
                payload = {"config_valid": True, "tls_certificate_sha256": certificate_sha256(config.tls_certificate), "capabilities": executor.capabilities()}
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0
            if args.worker_command == "serve":
                serve_worker(args.config, harness)
                return 0
        if args.command == "remote":
            if args.remote_command == "probe":
                endpoint = RemoteEndpoint.load(args.endpoint, trust_home=manager.home)
                result = probe_remote_endpoint(endpoint, timeout=args.timeout)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.remote_command == "test":
                endpoint = RemoteEndpoint.load(args.endpoint, trust_home=manager.home)
                root = args.root.resolve()
                entrypoint = args.entrypoint.resolve()
                files = [entrypoint, *(item.resolve() for item in args.include)]
                options = {}
                if args.options is not None:
                    options = json.loads(args.options.resolve().read_text(encoding="utf-8"))
                    if not isinstance(options, dict):
                        raise PSMatrixError("Remote worker options root must be an object")
                result = submit_remote_job(endpoint, root=root, files=files, entrypoint=entrypoint, options=options, timeout=args.timeout)
                if args.report_json is not None:
                    atomic_write_json(args.report_json.resolve(), result["report"])
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["report"].get("status") == "PASS" else 1
        if args.command == "hybrid":
            if args.hybrid_command == "test":
                remote_options = {}
                if args.remote_options is not None:
                    remote_options = json.loads(args.remote_options.resolve().read_text(encoding="utf-8"))
                    if not isinstance(remote_options, dict):
                        raise PSMatrixError("Hybrid remote options root must be an object")
                report = execute_hybrid_matrix(
                    home=manager.home, root=args.root, entrypoint=args.entrypoint,
                    local_runtimes=list(args.local_runtime), local_args=list(args.local_arg),
                    endpoint_paths=list(args.worker_endpoint), include=list(args.include),
                    remote_options=remote_options, timeout=args.timeout,
                )
                if args.report_json is not None:
                    atomic_write_json(args.report_json.resolve(), report)
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0 if report["status"] == "PASS" else 1
        if args.command == "full":
            if args.full_command == "init":
                result = write_full_matrix_template(args.output)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.full_command == "plan":
                result = plan_full_matrix(home=manager.home, spec_path=args.spec)
                if args.output is not None:
                    atomic_write_json(args.output.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("status") == "READY" else 1
            if args.full_command == "release-binding":
                result = build_full_matrix_release_binding(
                    release_manifest=args.release_manifest, artifact_dir=args.artifact_dir,
                    release_public_key=args.release_public_key, release_commit=args.release_commit, output=args.output,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.full_command == "attest":
                create_full_matrix_ga_attestation(
                    report_path=args.report, release_binding_path=args.release_binding,
                    private_key=args.private_key, public_key=args.public_key, output=args.output,
                )
                print(json.dumps({"output": str(args.output.resolve()), "valid": True}, ensure_ascii=False, indent=2))
                return 0
            if args.full_command == "verify-attestation":
                result = verify_full_matrix_ga_attestation(
                    read_json(args.attestation.resolve()), report_path=args.report, public_key=args.public_key,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.full_command == "test":
                remote_options = {}
                if args.remote_options is not None:
                    remote_options = json.loads(args.remote_options.resolve().read_text(encoding="utf-8"))
                    if not isinstance(remote_options, dict):
                        raise PSMatrixError("Full matrix remote options root must be an object")
                signing_values = [args.attestation, args.signing_private_key, args.signing_public_key, args.builder_id]
                if any(value is not None for value in signing_values):
                    if not all(value is not None for value in signing_values) or args.evidence_bundle is None:
                        raise PSMatrixError("Signed full-matrix provenance requires evidence, attestation, both keys, and builder id")
                report = execute_full_matrix(
                    home=manager.home, root=args.root, entrypoint=args.entrypoint,
                    spec_path=args.spec, include=list(args.include), local_args=list(args.local_arg),
                    remote_options=remote_options, timeout=args.timeout, jobs=args.jobs,
                    differential_mode=args.differential,
                )
                if args.report_json:
                    atomic_write_json(args.report_json.resolve(), report.to_dict())
                if args.report_junit:
                    write_junit(report, args.report_junit)
                if args.report_sarif:
                    write_sarif(report, args.report_sarif)
                if args.report_html:
                    write_html(report, args.report_html)
                if args.report_sbom:
                    write_sbom(report, args.report_sbom)
                if args.evidence_bundle:
                    write_evidence_bundle(report, args.evidence_bundle, project_root=args.root.resolve())
                    if args.attestation is not None:
                        statement = build_slsa_provenance(
                            artifact=args.evidence_bundle, report=report.to_dict(), builder_id=args.builder_id,
                        )
                        envelope = sign_provenance(statement, args.signing_private_key, args.signing_public_key)
                        write_attestation(args.attestation, envelope)
                if args.json:
                    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
                else:
                    print(render_human(report), end="")
                return 0 if report.status in {"PASS", "PASS_WITH_DIFFERENCES"} else 1
        if args.command == "adversarial":
            if args.adversarial_command == "list":
                print(json.dumps({"cases": list_adversarial_cases()}, ensure_ascii=False, indent=2))
                return 0
            report = run_adversarial_campaign(
                home=manager.home,
                runtime_version=args.runtime,
                strict=args.strict,
                categories=set(args.category) if args.category else None,
                output=args.report_json,
                evidence_bundle=args.evidence_bundle,
            )
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
            return 0 if report.status in {"PASS", "PASS_WITH_GAPS"} else 1
        if args.command == "recovery":
            default_queue = manager.home / "fleet" / "queue.sqlite3"
            default_backups = manager.home / "fleet" / "backups"
            if args.recovery_command == "list":
                print(json.dumps({"cases": list_recovery_cases(), "count": len(list_recovery_cases())}, ensure_ascii=False, indent=2))
                return 0
            if args.recovery_command == "run":
                if (args.private_key is None) != (args.public_key is None):
                    raise PSMatrixError("Recovery signing requires both --private-key and --public-key")
                if args.attestation is not None and args.private_key is None:
                    raise PSMatrixError("Recovery attestation requires signing keys")
                report = run_recovery_campaign(manager.home, private_key=args.private_key, public_key=args.public_key)
                if args.report_json is not None:
                    atomic_write_json(args.report_json.resolve(), report)
                if args.evidence_bundle is not None:
                    write_recovery_evidence(report, args.evidence_bundle)
                if args.attestation is not None:
                    atomic_write_json(args.attestation.resolve(), sign_recovery_report(report, args.private_key, args.public_key))
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0 if report.get("status") == "PASS" else 1
            if args.recovery_command == "verify-attestation":
                envelope = json.loads(args.attestation.resolve().read_text(encoding="utf-8"))
                print(json.dumps(verify_recovery_report(envelope, args.public_key), ensure_ascii=False, indent=2))
                return 0
            if args.recovery_command == "journal":
                journal = RecoveryJournal(args.path)
                result = journal.repair_torn_tail() if args.repair else journal.verify()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("valid", True) else 1
            if args.recovery_command.startswith("queue-"):
                queue_path = (args.queue or default_queue).resolve()
                queue = (
                    FleetQueue.recovery_handle(queue_path)
                    if args.recovery_command in {"queue-inspect", "queue-restore"}
                    else FleetQueue(queue_path)
                )
                manager_recovery = QueueRecovery(queue, (getattr(args, "backup_root", None) or default_backups).resolve())
                if args.recovery_command == "queue-inspect":
                    result = manager_recovery.inspect(full=args.full)
                elif args.recovery_command == "queue-backup":
                    backup = manager_recovery.backup()
                    result = {"database": str(backup.database), "manifest": str(backup.manifest), "backup_sha256": backup.backup_sha256}
                elif args.recovery_command == "queue-restore":
                    result = manager_recovery.restore_latest()
                else:
                    result = manager_recovery.reconcile()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("valid", True) is not False else 1
            if args.recovery_command == "transfer-audit":
                recovery = TransferRecovery(TransferStore((args.store or (manager.home / "fleet" / "transfers")).resolve()))
                result = recovery.repair() if args.repair else recovery.audit()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("invalid_chunks", result.get("audit", {}).get("invalid_chunks", 0)) == 0 else 1
        if args.command == "ops":
            service = ObservabilityService(manager.home)
            if args.ops_command == "snapshot":
                result = service.snapshot()
                if args.output:
                    atomic_write_json(args.output.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ops_command == "audit":
                result = service.audit_search(
                    action=args.action, query=args.query, session_id=args.session_id,
                    since=args.since, limit=args.limit,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if not result.get("invalid_chains") else 1
            if args.ops_command == "reports":
                result = service.report_history(status=args.status, limit=args.limit, root=args.root)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ops_command == "metrics":
                text = service.prometheus()
                if args.output:
                    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
                    args.output.resolve().write_text(text, encoding="utf-8", newline="\n")
                print(text, end="")
                return 0
            if args.ops_command == "support-bundle":
                result = service.build_support_bundle(args.output)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ops_command == "certificates":
                result = service.certificate_inventory(warning_days=args.warning_days)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("critical", 0) == 0 else 1
            if args.ops_command == "otlp-export":
                headers = dict(_parse_string_assignments(args.header, label="--header"))
                exporter = OTLPMetricsExporter(service, args.endpoint, headers=headers, timeout_seconds=args.timeout)
                result = exporter.export_once()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("valid") else 1
        if args.command == "ga":
            if args.ga_command == "init":
                result = write_ga_template(args.output)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "evaluate":
                result = evaluate_ga(args.policy, output=args.output)
                print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
                return 0 if result.status == "PASS" else (2 if result.status == "INCOMPLETE" else 1)
            if args.ga_command == "proof-create":
                value = json.loads(args.input.resolve().read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise PSMatrixError("GA proof input root must be an object")
                if value.get("proof_type") != args.type:
                    raise PSMatrixError("GA proof input type does not match --type")
                envelope = create_ga_proof(value, private_key=args.private_key, public_key=args.public_key)
                atomic_write_json(args.output.resolve(), envelope)
                print(json.dumps({"output": str(args.output.resolve()), "proof_type": args.type}, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "proof-verify":
                envelope = json.loads(args.attestation.resolve().read_text(encoding="utf-8"))
                result = verify_ga_proof(envelope, public_key=args.public_key, expected_type=args.type)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "review-packet":
                result = build_security_review_packet(
                    root=args.root,
                    source_archive=args.source_archive,
                    release_manifest=args.release_manifest,
                    output=args.output,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "review-finalize":
                result = finalize_security_review(
                    report_path=args.report,
                    source_archive=args.source_archive,
                    release_manifest=args.release_manifest,
                    private_key=args.private_key,
                    public_key=args.public_key,
                    result_output=args.result_output,
                    attestation_output=args.attestation_output,
                )
                print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "artifact-sign":
                envelope = create_ga_artifact_attestation(
                    args.artifact, artifact_type=args.type, observed_at=args.observed_at,
                    private_key=args.private_key, public_key=args.public_key,
                )
                atomic_write_json(args.output.resolve(), envelope)
                print(json.dumps({"output": str(args.output.resolve()), "artifact_type": args.type}, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "artifact-verify":
                envelope = json.loads(args.attestation.resolve().read_text(encoding="utf-8"))
                result = verify_ga_artifact_attestation(
                    envelope, artifact=args.artifact, artifact_type=args.type, public_key=args.public_key,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "key-rotation-drill":
                envelope = run_key_rotation_drill(signing_private_key=args.private_key, signing_public_key=args.public_key)
                atomic_write_json(args.output.resolve(), envelope)
                print(json.dumps({"output": str(args.output.resolve()), "valid": True}, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "sign":
                envelope, evaluation = sign_ga_policy(
                    args.policy, private_key=args.private_key, public_key=args.public_key,
                    evaluation_output=args.evaluation_output,
                )
                atomic_write_json(args.output.resolve(), envelope)
                print(json.dumps({
                    "output": str(args.output.resolve()), "status": "PASS",
                    "policy_sha256": evaluation.policy_sha256,
                }, ensure_ascii=False, indent=2))
                return 0
            if args.ga_command == "verify":
                envelope = json.loads(args.attestation.resolve().read_text(encoding="utf-8"))
                result = verify_ga_attestation(envelope, public_key=args.public_key)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        if args.command == "mcp":
            return serve_stdio(args.root.resolve(), manager.home)
        if args.command == "mcp-http":
            if args.mcp_http_command == "build-bootstrap":
                result = build_web_ai_bundle(
                    Path(__file__).resolve().parents[2], args.output,
                    public_url=args.public_url, auth_mode=args.auth_mode, version=__version__,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            scheme = "https" if args.tls_cert else "http"
            public_url = args.public_url or f"{scheme}://{args.host}:{args.port}{args.endpoint}"
            auth = HTTPAuthConfig.load(args.auth_config, resource_url=public_url)
            hosts = tuple(args.allowed_host or [args.host, "localhost", "127.0.0.1"])
            limits = SessionLimits(
                max_files=args.max_files,
                max_project_bytes=args.max_project_bytes,
                max_upload_bytes=args.max_upload_bytes,
                ttl_seconds=args.session_ttl,
                artifact_ttl_seconds=args.artifact_ttl,
            )
            config = HTTPMCPConfig(
                host=args.host, port=args.port, endpoint=args.endpoint, public_url=public_url,
                allowed_origins=tuple(args.allowed_origin), allowed_hosts=hosts,
                max_message_bytes=args.max_message_bytes, rate_per_minute=args.rate_per_minute,
                burst=args.burst, max_concurrent_per_session=args.max_concurrent,
                validation_workers=args.validation_workers,
                tls_certificate=args.tls_cert.resolve() if args.tls_cert else None,
                tls_private_key=args.tls_key.resolve() if args.tls_key else None,
                client_ca=args.client_ca.resolve() if args.client_ca else None,
                auth_config=auth, openai_challenge=os.environ.get(args.openai_challenge_env),
                dashboard_enabled=not args.disable_dashboard,
                metrics_enabled=not args.disable_metrics,
                otlp_endpoint=args.otlp_endpoint,
                otlp_headers=_parse_string_assignments(args.otlp_header, label="--otlp-header"),
                otlp_interval_seconds=args.otlp_interval,
                session_limits=limits,
            )
            return serve_http(config, manager.home)
        if args.command == "channels":
            print(
                json.dumps(
                    {
                        "channels": {name: channel.__dict__ for name, channel in BUILTIN_CHANNELS.items()},
                        "matrices": {name: list(values) for name, values in MATRICES.items()},
                        "core_release_lines": [release.__dict__ for release in CORE_RELEASE_LINES],
                        "oci_image_candidates": {
                            version: candidate.__dict__
                            for version, candidate in OCI_IMAGE_CANDIDATES.items()
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.command == "runtime":
            arch = getattr(args, "arch", None) or normalize_arch()
            if args.runtime_command == "list":
                print(json.dumps({"native": manager.list_installed(), "oci": oci.list_installed()}, ensure_ascii=False, indent=2))
                return 0
            if args.runtime_command == "install-matrix":
                results = []
                for version in matrix_versions(args.matrix):
                    spec = resolve_runtime(version, arch, args.libc)
                    try:
                        results.append(
                            _install_target(
                                manager, oci, spec,
                                backend=args.backend, engine=args.engine, force=args.force,
                            )
                        )
                    except (PSMatrixError, OSError, ValueError) as exc:
                        results.append({
                            "runtime_id": spec.runtime_id,
                            "backend": args.backend,
                            "status": "FAILED",
                            "error": str(exc),
                        })
                print(json.dumps({"matrix": args.matrix, "results": results}, ensure_ascii=False, indent=2))
                return 0 if all(item["status"] == "INSTALLED" for item in results) else 1
            spec = resolve_runtime(args.version, arch, args.libc)
            if args.runtime_command == "oci-install":
                payload = oci.install(
                    spec,
                    engine=args.engine,
                    image=args.image,
                    pull=not args.no_pull,
                    expected_digest=args.image_digest,
                    trust_local=args.trust_local_image,
                    force=args.force,
                )
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0
            if args.runtime_command == "oci-verify":
                payload = oci.probe(spec, engine=args.engine)
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0 if payload.get("version_match") else 1
            if args.runtime_command == "oci-remove":
                removed = oci.remove(spec)
                print(json.dumps({"runtime_id": spec.runtime_id, "backend": "oci", "removed": removed}))
                return 0
            if args.runtime_command == "install":
                installation = manager.install(
                    spec,
                    force=args.force,
                    archive_override=args.archive,
                    sha256_override=args.sha256,
                    hashes_override=args.hashes_file,
                )
                print(
                    json.dumps(
                        {
                            "runtime_id": installation.spec.runtime_id,
                            "path": str(installation.executable),
                            "sha256": installation.sha256,
                            "installed_at": installation.installed_at,
                        },
                        indent=2,
                    )
                )
                return 0
            if args.runtime_command == "remove":
                removed = manager.remove(spec)
                print(json.dumps({"runtime_id": spec.runtime_id, "removed": removed}))
                return 0
            if args.runtime_command == "verify":
                payload = manager.probe(spec)
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0 if payload["version_match"] else 1
        if args.command == "module":
            if args.module_command == "list":
                print(json.dumps(modules.list_installed(args.name), ensure_ascii=False, indent=2))
                return 0
            if args.module_command == "lock":
                exact_modules = dict(_parse_string_assignments(args.module, label="--module"))
                payload = modules.build_lock(
                    args.name or None,
                    selections=exact_modules or None,
                    require_verified=args.require_verified,
                )
                output = args.output.resolve()
                atomic_write_json(output, payload)
                print(json.dumps({
                    "output": str(output),
                    "module_count": len(payload["powershell_modules"]),
                    "require_verified": args.require_verified,
                }, ensure_ascii=False, indent=2))
                return 0
            if args.module_command == "install-nupkg":
                installation = modules.install_nupkg(
                    args.package,
                    expected_name=args.name,
                    expected_version=args.module_version,
                    sha256=args.sha256,
                    trust_local=args.trust_local,
                    force=args.force,
                )
                print(
                    json.dumps(
                        {
                            "name": installation.name,
                            "version": installation.version,
                            "path": str(installation.root),
                            "sha256": installation.sha256,
                            "verified": installation.verified,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return 0
        if args.command == "mirror":
            mirror_root = (args.root or (manager.home / "module-mirror")).resolve()
            mirror = OfflineModuleMirror(mirror_root)
            if args.mirror_command == "add":
                result = mirror.add(args.package, expected_sha256=args.sha256, source=args.source)
                print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
                return 0
            if args.mirror_command == "list":
                print(json.dumps(mirror.list(args.name), ensure_ascii=False, indent=2))
                return 0
            if args.mirror_command == "verify":
                result = mirror.verify()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["valid"] else 1
            if args.mirror_command == "export":
                print(json.dumps(mirror.export(args.output), ensure_ascii=False, indent=2))
                return 0
            if args.mirror_command == "install":
                print(json.dumps(mirror.install_into(modules, args.name, args.version), ensure_ascii=False, indent=2))
                return 0
            if args.mirror_command == "lock":
                selections = dict(_parse_string_assignments(args.module, label="--module"))
                result = resolve_mirror_lock(mirror, selections)
                atomic_write_json(args.output.resolve(), result)
                print(json.dumps({"output": str(args.output.resolve()), "modules": len(result["powershell_modules"]), "graph": result["psmatrix_graph"]}, ensure_ascii=False, indent=2))
                return 0
        if args.command == "compat":
            if args.compat_command == "init":
                print(json.dumps(write_compatibility_template(args.output), ensure_ascii=False, indent=2))
                return 0
            if args.compat_command == "scan":
                result = scan_project_dependencies(args.path)
                if args.output:
                    atomic_write_json(args.output.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.compat_command == "plan":
                result = plan_compatibility_matrix(
                    args.spec,
                    mirror_root=(args.mirror_root or (manager.home / "module-mirror")).resolve(),
                    runtime_home=manager.home,
                )
                if args.output:
                    atomic_write_json(args.output.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["status"] == "READY" else 1
            if args.compat_command == "run":
                result = execute_compatibility_matrix(
                    args.spec,
                    mirror_root=(args.mirror_root or (manager.home / "module-mirror")).resolve(),
                    home=manager.home,
                    output=args.output,
                    timeout=args.timeout,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["status"] == "PASS" else 1
        if args.command == "dependency":
            if args.dependency_command == "validate":
                lock = load_dependency_lock(args.lockfile)
                print(json.dumps({
                    "path": str(lock.path),
                    "sha256": lock.sha256,
                    "powershell_modules": len(lock.modules),
                    "native_commands": len(lock.native),
                    "normalized": lock.normalized(),
                }, ensure_ascii=False, indent=2))
                return 0
            if args.dependency_command == "init":
                output = args.output.resolve()
                if output.exists() and not args.force:
                    raise PSMatrixError(f"Dependency lockfile already exists: {output}")
                payload = {"schema": 1, "powershell_modules": [], "native_commands": []}
                atomic_write_json(output, payload)
                print(json.dumps({"output": str(output), "created": True}, indent=2))
                return 0
        if args.command == "scan":
            files = scan_powershell_files(args.path)
            if args.json:
                print(json.dumps([str(path) for path in files], ensure_ascii=False, indent=2))
            else:
                for path in files:
                    print(path)
            return 0
        if args.command == "test":
            return cmd_test(args, manager, modules)
        parser.error("Unhandled command")
        return 2
    except (PSMatrixError, ValueError, OSError) as exc:
        print(f"psmatrix: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
