from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


_INSTALLED = False
_ORIGINAL_PROOF_GATE: Callable[..., Any] | None = None
_ORIGINAL_CROSS_GATE: Callable[..., Any] | None = None


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number") from exc


def _external_otlp_gate(ga: Any, policy: dict[str, Any], base: Path) -> Any:
    gate = "external-otlp"
    evidence = policy.get("evidence") if isinstance(policy.get("evidence"), dict) else {}
    record = evidence.get(gate) if isinstance(evidence.get(gate), dict) else None
    if record is None or not record.get("path"):
        return ga.GateResult(gate, "INCOMPLETE", "Required signed proof is not configured", {})

    try:
        path = ga._safe_path(base, record["path"], f"{gate} evidence")
        public_key = ga._authority(
            policy,
            base,
            str(record.get("authority") or "operations"),
        )
        envelope = ga.read_json(path)
        if not isinstance(envelope, dict):
            raise ga.GAGateError("Signed proof root must be an object")
        proof = ga.verify_ga_proof(
            envelope,
            public_key=public_key,
            expected_type="external-otlp",
        )
        result = proof["result"]
        assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
        requirements = policy.get("requirements") if isinstance(policy.get("requirements"), dict) else {}
        maximum_age = max(
            1,
            min(int(requirements.get("external_proof_max_age_days") or 14), 180),
        )
        ga._require_fresh(result.get("observed_at"), "observed_at", maximum_age)
        ga._public_https(assertions, mode="external OTLP")

        if assertions.get("request_path") != "/v1/metrics":
            raise ga.GAGateError("External OTLP request path is not /v1/metrics")
        for key in (
            "collector_external",
            "authenticated_tls",
            "unauthenticated_request_rejected",
            "collector_receipt_verified",
            "restart_recovery_verified",
            "collector_instance_changed",
            "credential_leak_absent",
            "private_key_leak_absent",
            "source_body_leak_absent",
            "absolute_path_leak_absent",
            "release_commit_bound",
        ):
            if assertions.get(key) is not True:
                raise ga.GAGateError(f"External OTLP proof assertion failed: {key}")

        status_code = _integer(assertions.get("status_code"), "status_code")
        post_restart_status = _integer(
            assertions.get("post_restart_status_code"),
            "post_restart_status_code",
        )
        if not 200 <= status_code < 300:
            raise ga.GAGateError("External OTLP collector did not accept pre-restart metrics")
        if not 200 <= post_restart_status < 300:
            raise ga.GAGateError("External OTLP collector did not accept post-restart metrics")

        successful_exports = _integer(
            assertions.get("successful_exports"),
            "successful_exports",
        )
        if successful_exports < 2:
            raise ga.GAGateError("External OTLP proof requires at least two successful exports")
        recovery_seconds = _number(assertions.get("recovery_seconds"), "recovery_seconds")
        if not 0 < recovery_seconds <= 300:
            raise ga.GAGateError("External OTLP recovery exceeded the bounded 300-second limit")

        release_commit = str(assertions.get("release_commit") or "").lower()
        top_level_commit = str(result.get("release_commit") or "").lower()
        release_manifest = str(assertions.get("release_manifest_sha256") or "").lower()
        release_wheel = str(assertions.get("release_wheel_sha256") or "").lower()
        deployed_version = str(assertions.get("expected_version") or "")
        server_certificate = str(assertions.get("server_certificate_sha256") or "").lower()
        if ga._COMMIT_RE.fullmatch(release_commit) is None or top_level_commit != release_commit:
            raise ga.GAGateError("External OTLP release commit binding is invalid")
        if deployed_version != ga._GA_VERSION:
            raise ga.GAGateError(
                f"External OTLP proof is not for the final {ga._GA_VERSION} deployment"
            )
        for value, label in (
            (release_manifest, "release manifest"),
            (release_wheel, "release wheel"),
            (server_certificate, "server certificate"),
        ):
            if ga._SHA256_RE.fullmatch(value) is None:
                raise ga.GAGateError(f"External OTLP {label} binding is invalid")

        artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), list) else []
        if len(artifacts) != 1 or not isinstance(artifacts[0], dict):
            raise ga.GAGateError("External OTLP proof must bind exactly one live report")
        live_report = str(artifacts[0].get("sha256") or "").lower()
        if (
            artifacts[0].get("name") != "external-otlp-live-report.json"
            or ga._SHA256_RE.fullmatch(live_report) is None
        ):
            raise ga.GAGateError("External OTLP live-report subject is invalid")

        return ga.GateResult(
            gate,
            "PASS",
            "Signed external OTLP proof verified",
            {
                "path": str(path),
                "sha256": ga.sha256_file(path),
                "key_ids": proof["key_ids"],
                "observed_at": result.get("observed_at"),
                "endpoint": str(assertions.get("endpoint") or ""),
                "release_commit": release_commit,
                "release_manifest_sha256": release_manifest,
                "release_wheel_sha256": release_wheel,
                "deployed_version": deployed_version,
                "server_certificate_sha256": server_certificate,
                "live_report_sha256": live_report,
                "status_code": status_code,
                "post_restart_status_code": post_restart_status,
                "successful_exports": successful_exports,
                "recovery_seconds": recovery_seconds,
            },
        )
    except FileNotFoundError as exc:
        return ga.GateResult(gate, "INCOMPLETE", f"Evidence file is missing: {exc}", {})
    except (ga.PSMatrixError, OSError, ValueError, KeyError, TypeError) as exc:
        return ga.GateResult(gate, "FAIL", str(exc), {})


def _enforce_external_otlp_release_binding(ga: Any, results: list[Any]) -> list[Any]:
    by_gate = {item.gate: item for item in results}
    validation = by_gate.get("validation-summary")
    release = by_gate.get("signed-release")
    external = by_gate.get("external-otlp")
    if (
        validation is None
        or release is None
        or external is None
        or validation.status != "PASS"
        or release.status != "PASS"
        or external.status != "PASS"
    ):
        return results

    expected_commit = str(validation.evidence.get("git_commit") or "").lower()
    expected_manifest = str(release.evidence.get("sha256") or "").lower()
    wheel_digests = {
        str(value).lower() for value in release.evidence.get("wheel_sha256s") or []
    }
    reason = None
    if external.evidence.get("release_commit") != expected_commit:
        reason = "External OTLP proof does not bind the validated release commit"
    elif external.evidence.get("release_manifest_sha256") != expected_manifest:
        reason = "External OTLP proof does not bind the signed final release manifest"
    elif external.evidence.get("release_wheel_sha256") not in wheel_digests:
        reason = "External OTLP proof does not bind a wheel from the signed release"
    elif external.evidence.get("deployed_version") != ga._GA_VERSION:
        reason = f"External OTLP proof is not for the final {ga._GA_VERSION} deployment"

    if reason is None:
        return results
    replacement = ga.GateResult(
        external.gate,
        "FAIL",
        reason,
        external.evidence,
    )
    return [replacement if item.gate == "external-otlp" else item for item in results]


def install() -> None:
    global _INSTALLED, _ORIGINAL_PROOF_GATE, _ORIGINAL_CROSS_GATE
    if _INSTALLED:
        return
    from . import ga

    if getattr(ga, "_external_otlp_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_PROOF_GATE = ga._proof_gate
    _ORIGINAL_CROSS_GATE = ga._enforce_cross_gate_bindings

    def proof_gate(
        policy: dict[str, Any],
        base: Path,
        gate: str,
        proof_type: str,
        role: str,
    ) -> Any:
        if proof_type == "external-otlp":
            return _external_otlp_gate(ga, policy, base)
        assert _ORIGINAL_PROOF_GATE is not None
        return _ORIGINAL_PROOF_GATE(policy, base, gate, proof_type, role)

    def cross_gate(results: list[Any]) -> list[Any]:
        assert _ORIGINAL_CROSS_GATE is not None
        existing = _ORIGINAL_CROSS_GATE(results)
        return _enforce_external_otlp_release_binding(ga, existing)

    ga._proof_gate = proof_gate
    ga._enforce_cross_gate_bindings = cross_gate
    ga._external_otlp_hardened = True
    _INSTALLED = True
