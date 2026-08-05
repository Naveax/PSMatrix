from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import PSMatrixError
from .lab_provisioning import verify_authoritative_matrix_attestation
from .recovery import list_recovery_cases, verify_recovery_report
from .release import verify_release_manifest
from .signing import (
    TrustStore,
    canonical_json_bytes,
    create_dsse_envelope,
    generate_ed25519_keypair,
    public_key_id,
    sign_bytes,
    verify_bytes,
    verify_dsse_envelope,
)
from .util import atomic_write_json, read_json, sha256_file, utc_now_iso


class GAGateError(PSMatrixError):
    """Raised when Production GA evidence is malformed or unsafe."""


_GA_VERSION = "2.0.0"
_PROOF_PREDICATE = "https://psmatrix.dev/attestation/ga-proof/v1"
_GA_PREDICATE = "https://psmatrix.dev/attestation/production-ga/v1"
_ARTIFACT_PREDICATE = "https://psmatrix.dev/attestation/ga-artifact/v1"
_REQUIRED_GATES = (
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
)
_REQUIRED_REVIEW_SECTIONS = {
    "architecture", "authentication", "authorization", "sandbox", "supply-chain",
    "recovery", "operations", "privacy", "release-process",
}
_REQUIRED_REVIEW_METHODS = {
    "architecture-review", "threat-model-review", "manual-code-review", "test-evidence-review",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class GateResult:
    gate: str
    status: str
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class GAEvaluation:
    schema: int
    kind: str
    version: str
    evaluated_at: str
    policy_sha256: str
    status: str
    gates: tuple[GateResult, ...]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["gates"] = [asdict(item) for item in self.gates]
        return value


def _safe_path(base: Path, value: Any, label: str, *, directory: bool = False) -> Path:
    text = str(value or "")
    if not text or "\x00" in text or len(text) > 4096:
        raise GAGateError(f"{label} is missing or invalid")
    supplied = Path(text)
    candidate = (supplied if supplied.is_absolute() else base / supplied).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise GAGateError(f"{label} escapes the GA policy directory") from exc
    cursor = base.resolve()
    try:
        parts = candidate.relative_to(base.resolve()).parts
    except ValueError as exc:
        raise GAGateError(f"{label} is unsafe") from exc
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise GAGateError(f"{label} traverses a symlink")
    if directory:
        if not candidate.is_dir():
            raise FileNotFoundError(candidate)
    elif not candidate.is_file():
        raise FileNotFoundError(candidate)
    return candidate


def _digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _parse_time(value: Any, label: str) -> datetime:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GAGateError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise GAGateError(f"{label} requires a timezone")
    return parsed.astimezone(UTC)


def _require_fresh(value: Any, label: str, max_age_days: int) -> datetime:
    observed = _parse_time(value, label)
    now = datetime.now(UTC)
    if observed > now + timedelta(minutes=5):
        raise GAGateError(f"{label} is in the future")
    if now - observed > timedelta(days=max_age_days):
        raise GAGateError(f"{label} is older than {max_age_days} days")
    return observed


def _public_https(assertions: dict[str, Any], *, mode: str) -> None:
    endpoint = str(assertions.get("endpoint") or "")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GAGateError(f"{mode} proof requires a public HTTPS endpoint")
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise GAGateError(f"{mode} endpoint cannot be local")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise GAGateError(f"{mode} endpoint address is not globally routable")
    addresses = assertions.get("resolved_addresses")
    if not isinstance(addresses, list) or not addresses:
        raise GAGateError(f"{mode} proof requires externally resolved addresses")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(str(raw))
        except ValueError as exc:
            raise GAGateError(f"{mode} proof contains an invalid resolved address") from exc
        if not address.is_global:
            raise GAGateError(f"{mode} proof resolved to a non-public address")
    for key in ("external_probe", "public_dns", "public_tls"):
        if assertions.get(key) is not True:
            raise GAGateError(f"{mode} proof assertion failed: {key}")


def create_ga_artifact_attestation(
    artifact: Path, *, artifact_type: str, observed_at: str,
    private_key: Path, public_key: Path,
) -> dict[str, Any]:
    if artifact_type not in {"validation-summary", "full-matrix-report"}:
        raise GAGateError("Unsupported GA artifact attestation type")
    path = artifact.resolve()
    if not path.is_file() or path.is_symlink():
        raise GAGateError("GA artifact is missing or unsafe")
    _parse_time(observed_at, "observed_at")
    digest = sha256_file(path)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": path.name, "digest": {"sha256": digest}}],
        "predicateType": _ARTIFACT_PREDICATE,
        "predicate": {
            "schema": 1,
            "artifact_type": artifact_type,
            "observed_at": observed_at,
            "name": path.name,
            "sha256": digest,
            "size": path.stat().st_size,
        },
    }
    return create_dsse_envelope(statement, private_key.resolve(), public_key.resolve())


def verify_ga_artifact_attestation(
    envelope: dict[str, Any], *, artifact: Path, artifact_type: str,
    public_key: Path,
) -> dict[str, Any]:
    verified = verify_dsse_envelope(envelope, public_key.resolve())
    statement = verified["statement"]
    if statement.get("predicateType") != _ARTIFACT_PREDICATE:
        raise GAGateError("Unsupported GA artifact attestation predicate")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or predicate.get("schema") != 1 or predicate.get("artifact_type") != artifact_type:
        raise GAGateError("GA artifact attestation payload is malformed")
    path = artifact.resolve()
    digest = sha256_file(path)
    expected = [{"name": path.name, "digest": {"sha256": digest}}]
    if statement.get("subject") != expected:
        raise GAGateError("GA artifact attestation subject digest mismatch")
    if predicate.get("name") != path.name or predicate.get("sha256") != digest or predicate.get("size") != path.stat().st_size:
        raise GAGateError("GA artifact attestation metadata mismatch")
    _parse_time(predicate.get("observed_at"), "observed_at")
    return {"valid": True, "key_ids": verified["key_ids"], "predicate": predicate}


def create_ga_proof(
    result: dict[str, Any], *, private_key: Path, public_key: Path,
) -> dict[str, Any]:
    if not isinstance(result, dict) or result.get("schema") != 1 or result.get("kind") != "psmatrix.ga-proof-result":
        raise GAGateError("GA proof result schema is invalid")
    proof_type = str(result.get("proof_type") or "")
    if proof_type not in {
        "public-oauth", "public-mtls", "external-otlp", "key-rotation",
        "security-review", "vulnerability-scan",
    }:
        raise GAGateError("Unsupported GA proof type")
    if result.get("status") != "PASS":
        raise GAGateError("Only PASS GA proof results can be signed")
    observed = _parse_time(result.get("observed_at"), "observed_at")
    if observed > datetime.now(UTC) + timedelta(minutes=5):
        raise GAGateError("GA proof observed_at is in the future")
    artifacts = result.get("artifacts") or []
    if not isinstance(artifacts, list) or len(artifacts) > 256:
        raise GAGateError("GA proof artifacts are invalid")
    subjects = []
    for item in artifacts:
        if not isinstance(item, dict):
            raise GAGateError("GA proof artifact must be an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        if not name or Path(name).name != name or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise GAGateError("GA proof artifact metadata is invalid")
        subjects.append({"name": name, "digest": {"sha256": digest}})
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": _PROOF_PREDICATE,
        "predicate": result,
    }
    return create_dsse_envelope(statement, private_key.resolve(), public_key.resolve())


def verify_ga_proof(envelope: dict[str, Any], *, public_key: Path, expected_type: str) -> dict[str, Any]:
    verified = verify_dsse_envelope(envelope, public_key.resolve())
    statement = verified["statement"]
    if statement.get("predicateType") != _PROOF_PREDICATE:
        raise GAGateError("Unsupported GA proof predicate")
    result = statement.get("predicate")
    if not isinstance(result, dict) or result.get("schema") != 1 or result.get("kind") != "psmatrix.ga-proof-result":
        raise GAGateError("GA proof payload is malformed")
    if result.get("proof_type") != expected_type or result.get("status") != "PASS":
        raise GAGateError("GA proof type or status mismatch")
    _parse_time(result.get("observed_at"), "observed_at")
    expected_subject = []
    for item in result.get("artifacts") or []:
        expected_subject.append({"name": item["name"], "digest": {"sha256": item["sha256"]}})
    if statement.get("subject") != expected_subject:
        raise GAGateError("GA proof subjects do not bind the declared artifacts")
    return {"valid": True, "key_ids": verified["key_ids"], "result": result}


def _authority(policy: dict[str, Any], base: Path, role: str) -> Path:
    authorities = policy.get("authorities") if isinstance(policy.get("authorities"), dict) else {}
    record = authorities.get(role) if isinstance(authorities.get(role), dict) else None
    if record is None:
        raise GAGateError(f"GA authority is not configured: {role}")
    key = _safe_path(base, record.get("public_key"), f"authority {role} public_key")
    expected = str(record.get("key_id") or "")
    actual = public_key_id(key)
    if not expected or expected != actual:
        raise GAGateError(f"GA authority key identity mismatch: {role}")
    return key


def _proof_gate(policy: dict[str, Any], base: Path, gate: str, proof_type: str, role: str) -> GateResult:
    evidence = policy.get("evidence") if isinstance(policy.get("evidence"), dict) else {}
    record = evidence.get(gate) if isinstance(evidence.get(gate), dict) else None
    if record is None or not record.get("path"):
        return GateResult(gate, "INCOMPLETE", "Required signed proof is not configured", {})
    try:
        path = _safe_path(base, record["path"], f"{gate} evidence")
        public_key = _authority(policy, base, str(record.get("authority") or role))
        envelope = read_json(path)
        if not isinstance(envelope, dict):
            raise GAGateError("Signed proof root must be an object")
        proof = verify_ga_proof(envelope, public_key=public_key, expected_type=proof_type)
        result = proof["result"]
        assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        age_key = "security_review_max_age_days" if proof_type == "security-review" else (
            "vulnerability_max_age_days" if proof_type == "vulnerability-scan" else "external_proof_max_age_days"
        )
        default_age = 90 if proof_type == "security-review" else (30 if proof_type == "vulnerability-scan" else 14)
        _require_fresh(result.get("observed_at"), "observed_at", max(1, min(int(requirements.get(age_key) or default_age), 180)))
        if proof_type == "public-oauth":
            _public_https(assertions, mode="public OAuth")
            for key in ("oauth_external", "audience_verified", "scope_verified", "token_expiry_verified"):
                if assertions.get(key) is not True:
                    raise GAGateError(f"public OAuth proof assertion failed: {key}")
        elif proof_type == "public-mtls":
            _public_https(assertions, mode="public mTLS")
            for key in ("client_certificate_required", "untrusted_client_rejected", "certificate_rotation_ready"):
                if assertions.get(key) is not True:
                    raise GAGateError(f"public mTLS proof assertion failed: {key}")
        elif proof_type == "external-otlp":
            _public_https(assertions, mode="external OTLP")
            if assertions.get("collector_external") is not True or assertions.get("request_path") != "/v1/metrics":
                raise GAGateError("External OTLP collector proof is incomplete")
            status_code = int(assertions.get("status_code") or 0)
            if not 200 <= status_code < 300:
                raise GAGateError("External OTLP collector did not accept metrics")
        elif proof_type == "key-rotation":
            for key in ("old_signature_rejected", "new_signature_accepted", "old_key_retired", "revocation_enforced"):
                if assertions.get(key) is not True:
                    raise GAGateError(f"Key rotation proof assertion failed: {key}")
            if int(assertions.get("trust_generation") or 0) < 2:
                raise GAGateError("Key rotation proof did not advance trust generation")
        elif proof_type == "security-review":
            counts = assertions.get("findings") if isinstance(assertions.get("findings"), dict) else {}
            normalized_counts: dict[str, int] = {}
            for severity in ("critical", "high", "medium", "low", "info"):
                raw = counts.get(severity, 0)
                if isinstance(raw, bool):
                    raise GAGateError("Security review finding counts are invalid")
                try:
                    number = int(raw)
                except (TypeError, ValueError) as exc:
                    raise GAGateError("Security review finding counts are invalid") from exc
                if number < 0:
                    raise GAGateError("Security review finding counts are invalid")
                normalized_counts[severity] = number
            if normalized_counts["critical"] or normalized_counts["high"]:
                raise GAGateError("Security review contains critical or high findings")

            sections = set(str(item) for item in assertions.get("sections") or [])
            if not _REQUIRED_REVIEW_SECTIONS.issubset(sections):
                raise GAGateError("Security review scope is incomplete")
            methodologies = set(str(item) for item in assertions.get("methodologies") or [])
            if not _REQUIRED_REVIEW_METHODS.issubset(methodologies):
                raise GAGateError("Security review methodology is incomplete")
            if assertions.get("independent_review") is not True:
                raise GAGateError("Security review is not independently attested")

            reviewer = assertions.get("reviewer") if isinstance(assertions.get("reviewer"), dict) else {}
            for field in ("name", "organization", "role", "contact"):
                value = str(reviewer.get(field) or "").strip()
                if not value or len(value) > 256:
                    raise GAGateError(f"Security reviewer identity field is invalid: {field}")
            if reviewer.get("conflict_of_interest") is not False:
                raise GAGateError("Security reviewer conflict-of-interest declaration is invalid")
            if reviewer.get("key_controlled_by_reviewer") is not True:
                raise GAGateError("Security reviewer does not attest control of the signing key")

            reviewed_commit = str(assertions.get("reviewed_commit") or "").lower()
            release_digest = str(assertions.get("reviewed_release_sha256") or "").lower()
            source_digest = str(assertions.get("reviewed_source_sha256") or "").lower()
            report_digest = str(assertions.get("review_report_sha256") or "").lower()
            if _COMMIT_RE.fullmatch(reviewed_commit) is None:
                raise GAGateError("Security review commit binding is invalid")
            if _SHA256_RE.fullmatch(release_digest) is None:
                raise GAGateError("Security review release digest binding is invalid")
            if _SHA256_RE.fullmatch(source_digest) is None:
                raise GAGateError("Security review source digest binding is invalid")
            if _SHA256_RE.fullmatch(report_digest) is None:
                raise GAGateError("Security review report digest binding is invalid")
            artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), list) else []
            if not any(str(item.get("sha256") or "").lower() == report_digest for item in artifacts if isinstance(item, dict)):
                raise GAGateError("Security review report digest is not bound as a proof subject")
            review_hours = assertions.get("review_hours")
            if isinstance(review_hours, bool):
                raise GAGateError("Security review duration is invalid")
            try:
                hours = float(review_hours)
            except (TypeError, ValueError) as exc:
                raise GAGateError("Security review duration is invalid") from exc
            if not 0 < hours <= 1000:
                raise GAGateError("Security review duration is invalid")
        elif proof_type == "vulnerability-scan":
            counts = assertions.get("findings") if isinstance(assertions.get("findings"), dict) else {}
            if int(counts.get("critical") or 0) or int(counts.get("high") or 0):
                raise GAGateError("Vulnerability scan contains critical or high findings")
            scanners = assertions.get("scanners")
            if not isinstance(scanners, list) or len(set(str(item) for item in scanners)) < 2:
                raise GAGateError("Vulnerability proof requires at least two scanner classes")
            if assertions.get("source_scanned") is not True or assertions.get("dependencies_scanned") is not True:
                raise GAGateError("Vulnerability proof did not scan source and dependencies")
        gate_evidence: dict[str, Any] = {
            "path": str(path), "sha256": sha256_file(path), "key_ids": proof["key_ids"],
            "observed_at": result.get("observed_at"),
        }
        if proof_type == "security-review":
            gate_evidence.update({
                "reviewed_commit": str(assertions.get("reviewed_commit") or "").lower(),
                "reviewed_release_sha256": str(assertions.get("reviewed_release_sha256") or "").lower(),
                "reviewed_source_sha256": str(assertions.get("reviewed_source_sha256") or "").lower(),
                "review_report_sha256": str(assertions.get("review_report_sha256") or "").lower(),
            })
        elif proof_type == "vulnerability-scan":
            release_commit = str(assertions.get("release_commit") or "").lower()
            wheel_digest = str(assertions.get("release_wheel_sha256") or "").lower()
            if _COMMIT_RE.fullmatch(release_commit) is None:
                raise GAGateError("Vulnerability proof release commit binding is invalid")
            if _SHA256_RE.fullmatch(wheel_digest) is None:
                raise GAGateError("Vulnerability proof wheel digest binding is invalid")
            gate_evidence.update({"release_commit": release_commit, "release_wheel_sha256": wheel_digest})
        return GateResult(gate, "PASS", "Signed proof verified", gate_evidence)
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, KeyError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def _validation_gate(policy: dict[str, Any], base: Path) -> GateResult:
    gate = "validation-summary"
    record = (policy.get("evidence") or {}).get(gate) if isinstance(policy.get("evidence"), dict) else None
    if not isinstance(record, dict) or not record.get("path"):
        return GateResult(gate, "INCOMPLETE", "Validation summary is not configured", {})
    try:
        path = _safe_path(base, record["path"], "validation summary")
        attestation = _safe_path(base, record.get("attestation"), "validation summary attestation")
        key = _authority(policy, base, str(record.get("authority") or "ci"))
        signed = verify_ga_artifact_attestation(
            read_json(attestation), artifact=path, artifact_type="validation-summary", public_key=key,
        )
        value = read_json(path)
        if not isinstance(value, dict) or value.get("status") != "PASS":
            raise GAGateError("Validation summary status is not PASS")
        if value.get("version") != _GA_VERSION:
            raise GAGateError("Validation summary is not for final version 2.0.0")
        git_commit = str(value.get("git_commit") or "").lower()
        if _COMMIT_RE.fullmatch(git_commit) is None:
            raise GAGateError("Validation summary exact git_commit binding is missing or invalid")
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        _require_fresh(value.get("validated_at"), "validation validated_at", max(1, min(int(requirements.get("validation_max_age_days") or 7), 30)))
        tests = value.get("automated_tests") if isinstance(value.get("automated_tests"), dict) else {}
        if int(tests.get("failed") or 0) != 0 or int(tests.get("skipped") or tests.get("real_worker_skips") or 0) != 0:
            raise GAGateError("Validation summary contains failed or skipped tests")
        passed = int(tests.get("passed") or 0)
        total = int(tests.get("total") or passed)
        if passed <= 0 or passed != total:
            raise GAGateError("Validation test accounting is incomplete")
        reproducibility = value.get("reproducibility") if isinstance(value.get("reproducibility"), dict) else {}
        required_repro = {"source_zip", "source_tar_gz", "wheel"}
        if not all(reproducibility.get(item) is True for item in required_repro):
            raise GAGateError("Source/wheel reproducibility is not fully proven")
        if int(value.get("offline_install_exit_code", -1)) != 0:
            raise GAGateError("Offline installation did not exit successfully")
        if value.get("core_release_signature_valid") is not True or value.get("distribution_signature_valid") is not True:
            raise GAGateError("Validation summary lacks valid release signatures")
        return GateResult(gate, "PASS", "Core validation summary passed", {
            "path": str(path), "sha256": sha256_file(path), "tests": total,
            "git_commit": git_commit,
            "attestation": str(attestation), "key_ids": signed["key_ids"],
        })
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def _release_gate(policy: dict[str, Any], base: Path) -> GateResult:
    gate = "signed-release"
    record = (policy.get("evidence") or {}).get(gate) if isinstance(policy.get("evidence"), dict) else None
    if not isinstance(record, dict):
        return GateResult(gate, "INCOMPLETE", "Signed release evidence is not configured", {})
    try:
        manifest = _safe_path(base, record.get("manifest"), "release manifest")
        artifact_dir = _safe_path(base, record.get("artifact_dir"), "release artifact directory", directory=True)
        key = _authority(policy, base, str(record.get("authority") or "release"))
        result = verify_release_manifest(manifest, artifact_dir, signing_public_key=key)
        if result.get("valid") is not True or result.get("version") != _GA_VERSION:
            raise GAGateError("Signed release is not the final 2.0.0 release")
        manifest_root = read_json(manifest)
        manifest_value = manifest_root.get("manifest") if isinstance(manifest_root, dict) else None
        artifact_items = manifest_value.get("artifacts") if isinstance(manifest_value, dict) else None
        if not isinstance(artifact_items, list):
            raise GAGateError("Signed release artifact digest inventory is unavailable")
        artifact_digests = {
            str(item.get("name")): str(item.get("sha256")).lower()
            for item in artifact_items if isinstance(item, dict)
        }
        source_digests = sorted(
            digest for name, digest in artifact_digests.items()
            if name.endswith("-source.zip") and _SHA256_RE.fullmatch(digest)
        )
        wheel_digests = sorted(
            digest for name, digest in artifact_digests.items()
            if name.endswith(".whl") and _SHA256_RE.fullmatch(digest)
        )
        if not source_digests or not wheel_digests:
            raise GAGateError("Signed release must bind source ZIP and wheel artifacts")
        return GateResult(gate, "PASS", "Signed 2.0.0 release verified", {
            "manifest": str(manifest), "sha256": sha256_file(manifest), "artifacts": len(result.get("artifacts") or []),
            "source_sha256s": source_digests, "wheel_sha256s": wheel_digests,
        })
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def _windows_gate(policy: dict[str, Any], base: Path) -> GateResult:
    gate = "authoritative-windows"
    record = (policy.get("evidence") or {}).get(gate) if isinstance(policy.get("evidence"), dict) else None
    if not isinstance(record, dict) or not record.get("path"):
        return GateResult(gate, "INCOMPLETE", "Authoritative Windows evidence is not configured", {})
    try:
        path = _safe_path(base, record["path"], "authoritative Windows attestation")
        key = _authority(policy, base, str(record.get("authority") or "windows-lab"))
        result = verify_authoritative_matrix_attestation(path, public_key=key)
        statement = verify_dsse_envelope(read_json(path), key)["statement"]
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        _require_fresh(predicate.get("created_at"), "Windows matrix created_at", max(1, min(int(requirements.get("windows_max_age_days") or 30), 90)))
        if result.get("valid") is not True or result.get("campaign_count") != 3:
            raise GAGateError("Authoritative Windows matrix is incomplete")
        expected = ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"]
        if result.get("runtimes") != expected:
            raise GAGateError("Authoritative Windows runtime set is not exact")
        return GateResult(gate, "PASS", "Authoritative Windows matrix verified", {
            "path": str(path), "sha256": sha256_file(path), "runtimes": expected,
        })
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def _matrix_gate(policy: dict[str, Any], base: Path) -> GateResult:
    gate = "complete-runtime-matrix"
    record = (policy.get("evidence") or {}).get(gate) if isinstance(policy.get("evidence"), dict) else None
    if not isinstance(record, dict) or not record.get("path"):
        return GateResult(gate, "INCOMPLETE", "Complete runtime matrix report is not configured", {})
    try:
        path = _safe_path(base, record["path"], "complete runtime matrix report")
        attestation = _safe_path(base, record.get("attestation"), "complete runtime matrix attestation")
        key = _authority(policy, base, str(record.get("authority") or "ci"))
        signed = verify_ga_artifact_attestation(
            read_json(attestation), artifact=path, artifact_type="full-matrix-report", public_key=key,
        )
        report = read_json(path)
        if not isinstance(report, dict) or report.get("status") != "PASS":
            raise GAGateError("Complete runtime matrix status is not PASS")
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        _require_fresh(report.get("finished_at"), "full matrix finished_at", max(1, min(int(requirements.get("matrix_max_age_days") or 7), 30)))
        matrix = report.get("matrix") if isinstance(report.get("matrix"), dict) else {}
        coverage = matrix.get("coverage") if isinstance(matrix.get("coverage"), dict) else {}
        required = max(25, int((policy.get("requirements") or {}).get("full_matrix_targets") or 25))
        if int(coverage.get("declared") or 0) < required or int(coverage.get("passed") or 0) != int(coverage.get("declared") or 0):
            raise GAGateError("Complete runtime matrix did not pass every declared target")
        if int(coverage.get("incomplete") or 0) or int(coverage.get("failed") or 0):
            raise GAGateError("Complete runtime matrix contains incomplete or failed targets")
        if coverage.get("missing_required") or coverage.get("failed_required"):
            raise GAGateError("Complete runtime matrix required coverage is incomplete")
        if int(matrix.get("unallowed_differences") or 0):
            raise GAGateError("Complete runtime matrix contains unallowed differences")
        return GateResult(gate, "PASS", "Complete runtime matrix verified", {
            "path": str(path), "sha256": sha256_file(path), "targets": coverage.get("declared"),
            "attestation": str(attestation), "key_ids": signed["key_ids"],
        })
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def _recovery_gate(policy: dict[str, Any], base: Path) -> GateResult:
    gate = "disaster-recovery"
    record = (policy.get("evidence") or {}).get(gate) if isinstance(policy.get("evidence"), dict) else None
    if not isinstance(record, dict) or not record.get("path"):
        return GateResult(gate, "INCOMPLETE", "Disaster recovery attestation is not configured", {})
    try:
        path = _safe_path(base, record["path"], "recovery attestation")
        key = _authority(policy, base, str(record.get("authority") or "recovery"))
        envelope = read_json(path)
        result = verify_recovery_report(envelope, key)
        report = result["report"]
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        _require_fresh(report.get("finished_at"), "recovery finished_at", max(1, min(int(requirements.get("recovery_max_age_days") or 30), 90)))
        expected = {item["id"] for item in list_recovery_cases()}
        cases = report.get("cases") if isinstance(report.get("cases"), list) else []
        actual = {str(item.get("id")) for item in cases if isinstance(item, dict) and item.get("status") == "PASS"}
        if report.get("status") != "PASS" or actual != expected or int((report.get("summary") or {}).get("failed") or 0):
            raise GAGateError("Disaster recovery campaign is incomplete")
        return GateResult(gate, "PASS", "Disaster recovery campaign verified", {
            "path": str(path), "sha256": sha256_file(path), "cases": len(actual),
        })
    except FileNotFoundError as exc:
        return GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (PSMatrixError, OSError, ValueError, TypeError) as exc:
        return GateResult(gate, "FAIL", str(exc), {})


def load_ga_policy(path: Path) -> tuple[dict[str, Any], Path]:
    policy_path = path.resolve()
    value = read_json(policy_path)
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.ga-policy":
        raise GAGateError("Unsupported GA policy schema")
    if value.get("version") != _GA_VERSION:
        raise GAGateError("GA policy must target version 2.0.0")
    gates = value.get("required_gates")
    if gates is not None and set(str(item) for item in gates) != set(_REQUIRED_GATES):
        raise GAGateError("GA policy cannot remove or replace mandatory gates")
    authorities = value.get("authorities") if isinstance(value.get("authorities"), dict) else {}
    required_roles = {"release", "ci", "windows-lab", "deployment", "operations", "recovery", "security-review", "vulnerability-scanner"}
    if not required_roles.issubset(authorities):
        raise GAGateError("GA policy authority set is incomplete")
    configured = []
    for role in sorted(required_roles):
        record = authorities.get(role) if isinstance(authorities.get(role), dict) else {}
        key_id = str(record.get("key_id") or "")
        if key_id.startswith("sha256:") and len(key_id) == 71:
            configured.append((role, key_id))
    duplicates = {key_id for _, key_id in configured if sum(item == key_id for _, item in configured) > 1}
    if duplicates:
        raise GAGateError("Independent GA authority roles cannot share a signing key")
    return value, policy_path.parent


def _enforce_cross_gate_bindings(results: list[GateResult]) -> list[GateResult]:
    by_gate = {item.gate: item for item in results}
    validation = by_gate.get("validation-summary")
    release = by_gate.get("signed-release")
    if validation is None or release is None or validation.status != "PASS" or release.status != "PASS":
        return results
    expected_commit = str(validation.evidence.get("git_commit") or "").lower()
    expected_release = str(release.evidence.get("sha256") or "").lower()
    source_digests = set(str(item).lower() for item in release.evidence.get("source_sha256s") or [])
    wheel_digests = set(str(item).lower() for item in release.evidence.get("wheel_sha256s") or [])
    replacements: dict[str, GateResult] = {}

    review = by_gate.get("security-review")
    if review is not None and review.status == "PASS":
        reason = None
        if review.evidence.get("reviewed_commit") != expected_commit:
            reason = "Security review does not bind the validated release commit"
        elif review.evidence.get("reviewed_release_sha256") != expected_release:
            reason = "Security review does not bind the signed final release manifest"
        elif review.evidence.get("reviewed_source_sha256") not in source_digests:
            reason = "Security review does not bind a source ZIP from the signed release"
        if reason:
            replacements[review.gate] = GateResult(review.gate, "FAIL", reason, review.evidence)

    vulnerability = by_gate.get("vulnerability-scan")
    if vulnerability is not None and vulnerability.status == "PASS":
        reason = None
        if vulnerability.evidence.get("release_commit") != expected_commit:
            reason = "Vulnerability proof does not bind the validated release commit"
        elif vulnerability.evidence.get("release_wheel_sha256") not in wheel_digests:
            reason = "Vulnerability proof does not bind a wheel from the signed release"
        if reason:
            replacements[vulnerability.gate] = GateResult(vulnerability.gate, "FAIL", reason, vulnerability.evidence)

    return [replacements.get(item.gate, item) for item in results]


def evaluate_ga(policy_path: Path, *, output: Path | None = None) -> GAEvaluation:
    policy, base = load_ga_policy(policy_path)
    results = [
        _validation_gate(policy, base),
        _release_gate(policy, base),
        _windows_gate(policy, base),
        _matrix_gate(policy, base),
        _proof_gate(policy, base, "public-oauth", "public-oauth", "deployment"),
        _proof_gate(policy, base, "public-mtls", "public-mtls", "deployment"),
        _proof_gate(policy, base, "external-otlp", "external-otlp", "operations"),
        _proof_gate(policy, base, "key-rotation", "key-rotation", "release"),
        _recovery_gate(policy, base),
        _proof_gate(policy, base, "security-review", "security-review", "security-review"),
        _proof_gate(policy, base, "vulnerability-scan", "vulnerability-scan", "vulnerability-scanner"),
    ]
    results = _enforce_cross_gate_bindings(results)
    by_name = {item.gate for item in results}
    if by_name != set(_REQUIRED_GATES):
        raise GAGateError("Internal GA gate coverage mismatch")
    counts = {name: sum(item.status == name for item in results) for name in ("PASS", "FAIL", "INCOMPLETE")}
    status = "FAIL" if counts["FAIL"] else ("INCOMPLETE" if counts["INCOMPLETE"] else "PASS")
    evaluation = GAEvaluation(
        schema=1,
        kind="psmatrix.production-ga-evaluation",
        version=_GA_VERSION,
        evaluated_at=utc_now_iso(),
        policy_sha256=sha256_file(policy_path.resolve()),
        status=status,
        gates=tuple(results),
        summary={**counts, "total": len(results)},
    )
    if output is not None:
        atomic_write_json(output.resolve(), evaluation.to_dict())
    return evaluation


def create_ga_attestation(
    evaluation: dict[str, Any], *, private_key: Path, public_key: Path,
) -> dict[str, Any]:
    if not isinstance(evaluation, dict) or evaluation.get("kind") != "psmatrix.production-ga-evaluation":
        raise GAGateError("Production GA evaluation is malformed")
    if evaluation.get("version") != _GA_VERSION or evaluation.get("status") != "PASS":
        raise GAGateError("Production GA attestation requires a complete PASS evaluation")
    gates = evaluation.get("gates") if isinstance(evaluation.get("gates"), list) else []
    if len(gates) != len(_REQUIRED_GATES) or any(not isinstance(item, dict) or item.get("status") != "PASS" for item in gates):
        raise GAGateError("Production GA evaluation does not contain only passing mandatory gates")
    if {str(item.get("gate")) for item in gates} != set(_REQUIRED_GATES):
        raise GAGateError("Production GA evaluation does not contain every passing gate")
    digest = _digest_json(evaluation)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "psmatrix-2.0.0-production-ga", "digest": {"sha256": digest}}],
        "predicateType": _GA_PREDICATE,
        "predicate": evaluation,
    }
    return create_dsse_envelope(statement, private_key.resolve(), public_key.resolve())


def sign_ga_policy(
    policy_path: Path, *, private_key: Path, public_key: Path,
    evaluation_output: Path | None = None,
) -> tuple[dict[str, Any], GAEvaluation]:
    evaluation = evaluate_ga(policy_path, output=evaluation_output)
    if evaluation.status != "PASS":
        raise GAGateError(f"Production GA policy evaluation is {evaluation.status}, not PASS")
    return create_ga_attestation(
        evaluation.to_dict(), private_key=private_key, public_key=public_key
    ), evaluation


def verify_ga_attestation(envelope: dict[str, Any], *, public_key: Path) -> dict[str, Any]:
    verified = verify_dsse_envelope(envelope, public_key.resolve())
    statement = verified["statement"]
    if statement.get("predicateType") != _GA_PREDICATE:
        raise GAGateError("Unsupported Production GA attestation predicate")
    evaluation = statement.get("predicate")
    if not isinstance(evaluation, dict) or evaluation.get("status") != "PASS" or evaluation.get("version") != _GA_VERSION:
        raise GAGateError("Production GA attestation does not contain a valid PASS evaluation")
    gates = evaluation.get("gates") if isinstance(evaluation.get("gates"), list) else []
    if len(gates) != len(_REQUIRED_GATES) or any(not isinstance(item, dict) or item.get("status") != "PASS" for item in gates):
        raise GAGateError("Production GA attestation contains a non-PASS or duplicate gate")
    if {str(item.get("gate")) for item in gates} != set(_REQUIRED_GATES):
        raise GAGateError("Production GA attestation gate set is incomplete")
    digest = _digest_json(evaluation)
    subjects = statement.get("subject") or []
    if subjects != [{"name": "psmatrix-2.0.0-production-ga", "digest": {"sha256": digest}}]:
        raise GAGateError("Production GA attestation subject digest mismatch")
    return {"valid": True, "key_ids": verified["key_ids"], "evaluation": evaluation}


def run_key_rotation_drill(*, signing_private_key: Path, signing_public_key: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="psmatrix-ga-key-rotation-") as temp:
        root = Path(temp)
        old_private, old_public = root / "old.pem", root / "old.pub"
        new_private, new_public = root / "new.pem", root / "new.pub"
        generate_ed25519_keypair(old_private, old_public)
        generate_ed25519_keypair(new_private, new_public)
        trust = TrustStore(root / "home")
        old = trust.add("ga-drill", "release", old_public)
        rotated = trust.rotate("ga-drill", "release", new_public, expected_current_key_id=old.key_id)
        payload = b"psmatrix-production-ga-key-rotation"
        old_signature = sign_bytes(payload, old_private)
        new_signature = sign_bytes(payload, new_private)
        active = trust.get("ga-drill", "release")
        old_rejected = not verify_bytes(payload, old_signature, active.public_key)
        new_accepted = verify_bytes(payload, new_signature, active.public_key)
        revoked = trust.revoke("ga-drill", "release", reason="bounded GA revocation drill")
        revocation_enforced = False
        try:
            trust.get("ga-drill", "release")
        except Exception:
            revocation_enforced = True
        result = {
            "schema": 1,
            "kind": "psmatrix.ga-proof-result",
            "proof_type": "key-rotation",
            "status": "PASS",
            "observed_at": utc_now_iso(),
            "assertions": {
                "old_signature_rejected": old_rejected,
                "new_signature_accepted": new_accepted,
                "old_key_retired": any(item.get("key_id") == old.key_id for item in revoked.get("history", [])),
                "revocation_enforced": revocation_enforced,
                "trust_generation": rotated and int(revoked.get("generation") or 0),
                "old_key_id": old.key_id,
                "new_key_id": rotated.key_id,
            },
            "artifacts": [],
        }
        if not all(result["assertions"].get(key) is True for key in (
            "old_signature_rejected", "new_signature_accepted", "old_key_retired", "revocation_enforced"
        )):
            raise GAGateError("Key rotation drill did not satisfy every assertion")
        return create_ga_proof(result, private_key=signing_private_key, public_key=signing_public_key)


def default_ga_policy() -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "psmatrix.ga-policy",
        "version": _GA_VERSION,
        "required_gates": list(_REQUIRED_GATES),
        "requirements": {
            "full_matrix_targets": 25,
            "validation_max_age_days": 7,
            "matrix_max_age_days": 7,
            "windows_max_age_days": 30,
            "recovery_max_age_days": 30,
            "external_proof_max_age_days": 14,
            "security_review_max_age_days": 90,
            "vulnerability_max_age_days": 30
        },
        "authorities": {
            "release": {"public_key": "keys/release.pem", "key_id": "REPLACE_KEY_ID"},
            "ci": {"public_key": "keys/ci.pem", "key_id": "REPLACE_KEY_ID"},
            "windows-lab": {"public_key": "keys/windows-lab.pem", "key_id": "REPLACE_KEY_ID"},
            "deployment": {"public_key": "keys/deployment.pem", "key_id": "REPLACE_KEY_ID"},
            "operations": {"public_key": "keys/operations.pem", "key_id": "REPLACE_KEY_ID"},
            "recovery": {"public_key": "keys/recovery.pem", "key_id": "REPLACE_KEY_ID"},
            "security-review": {"public_key": "keys/security-review.pem", "key_id": "REPLACE_KEY_ID"},
            "vulnerability-scanner": {"public_key": "keys/vulnerability-scanner.pem", "key_id": "REPLACE_KEY_ID"},
        },
        "evidence": {
            "validation-summary": {"path": "evidence/validation-summary.json", "attestation": "evidence/validation-summary.dsse.json", "authority": "ci"},
            "signed-release": {"manifest": "release/psmatrix-2.0.0-release.json", "artifact_dir": "release", "authority": "release"},
            "authoritative-windows": {"path": "evidence/windows-authoritative.dsse.json", "authority": "windows-lab"},
            "complete-runtime-matrix": {"path": "evidence/full-matrix-report.json", "attestation": "evidence/full-matrix-report.dsse.json", "authority": "ci"},
            "public-oauth": {"path": "evidence/public-oauth.dsse.json", "authority": "deployment"},
            "public-mtls": {"path": "evidence/public-mtls.dsse.json", "authority": "deployment"},
            "external-otlp": {"path": "evidence/external-otlp.dsse.json", "authority": "operations"},
            "key-rotation": {"path": "evidence/key-rotation.dsse.json", "authority": "release"},
            "disaster-recovery": {"path": "evidence/recovery.dsse.json", "authority": "recovery"},
            "security-review": {"path": "evidence/security-review.dsse.json", "authority": "security-review"},
            "vulnerability-scan": {"path": "evidence/vulnerability-scan.dsse.json", "authority": "vulnerability-scanner"},
        },
    }


def write_ga_template(path: Path) -> dict[str, Any]:
    output = path.resolve()
    if output.exists():
        raise GAGateError(f"Refusing to overwrite existing GA policy: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, default_ga_policy())
    return {"path": str(output), "sha256": sha256_file(output), "gates": len(_REQUIRED_GATES)}
