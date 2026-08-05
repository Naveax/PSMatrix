from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuntimeSpec:
    version: str
    os: str = "linux"
    arch: str = "x64"
    libc: str = "glibc"
    channel: str = "exact"

    @property
    def runtime_id(self) -> str:
        suffix = "" if self.libc == "glibc" else f"-{self.libc}"
        return f"powershell-{self.version}-{self.os}-{self.arch}{suffix}"

    @property
    def artifact_name(self) -> str:
        if self.os != "linux":
            raise ValueError(f"Unsupported local runtime OS: {self.os}")
        platform_name = "linux" if self.libc == "glibc" else f"linux-{self.libc}"
        return f"powershell-{self.version}-{platform_name}-{self.arch}.tar.gz"

    @property
    def release_tag(self) -> str:
        return f"v{self.version}"

    @property
    def download_url(self) -> str:
        return (
            "https://github.com/PowerShell/PowerShell/releases/download/"
            f"{self.release_tag}/{self.artifact_name}"
        )

    @property
    def hashes_url(self) -> str:
        return (
            "https://github.com/PowerShell/PowerShell/releases/download/"
            f"{self.release_tag}/hashes.sha256"
        )


@dataclass
class ParseDiagnostic:
    message: str
    error_id: str | None = None
    line: int | None = None
    column: int | None = None
    extent: str | None = None


@dataclass
class ExecutionResult:
    command: list[str]
    cwd: str
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    resource_violation: str | None = None


@dataclass
class VerificationCheck:
    kind: str
    passed: bool
    subject: str
    expected: Any = None
    actual: Any = None
    message: str | None = None


@dataclass
class FileChange:
    path: str
    change: str
    size_before: int | None = None
    size_after: int | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None


@dataclass
class TargetReport:
    runtime_id: str
    runtime_version: str
    source: str
    source_sha256: str
    status: str
    parse_ok: bool
    parse_diagnostics: list[ParseDiagnostic] = field(default_factory=list)
    execution: ExecutionResult | None = None
    test_execution: ExecutionResult | None = None
    tests: dict[str, Any] = field(default_factory=dict)
    verification: list[VerificationCheck] = field(default_factory=list)
    file_changes: list[FileChange] = field(default_factory=list)
    windows_requirements: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sandbox: dict[str, Any] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)
    observation: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)
    dependencies: dict[str, Any] = field(default_factory=dict)
    hooks: dict[str, Any] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MatrixReport:
    schema: int
    tool_version: str
    started_at: str
    finished_at: str
    status: str
    targets: list[TargetReport]
    differential: list[dict[str, Any]] = field(default_factory=list)
    matrix: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeInstallation:
    spec: RuntimeSpec
    root: Path
    executable: Path
    installed_at: str
    sha256: str


def execution_result_from_dict(value: dict[str, Any] | None) -> ExecutionResult | None:
    if value is None:
        return None
    return ExecutionResult(**value)


def target_report_from_dict(value: dict[str, Any]) -> TargetReport:
    payload = dict(value)
    payload["parse_diagnostics"] = [ParseDiagnostic(**item) for item in payload.get("parse_diagnostics", [])]
    payload["execution"] = execution_result_from_dict(payload.get("execution"))
    payload["test_execution"] = execution_result_from_dict(payload.get("test_execution"))
    payload["verification"] = [VerificationCheck(**item) for item in payload.get("verification", [])]
    payload["file_changes"] = [FileChange(**item) for item in payload.get("file_changes", [])]
    return TargetReport(**payload)
