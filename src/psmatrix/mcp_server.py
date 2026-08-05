from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .diagnostics import report_diagnostics
from .gate import create_gate_receipt, load_gate_receipt, verify_gate_receipt, write_gate_receipt
from .repair import (
    RepairError,
    apply_and_validate,
    build_repair_plan,
    propose_patch,
    resolve_project_file,
    run_validation,
)
from .scanner import scan_powershell_files
from .util import atomic_write_json, read_json, utc_now_iso
from .attestation import load_attestation, verify_provenance
from .hybrid import execute_hybrid_matrix
from .full_matrix import execute_full_matrix, plan_full_matrix, write_full_matrix_template
from .module_compat import OfflineModuleMirror, execute_compatibility_matrix, plan_compatibility_matrix, scan_project_dependencies
from .http_sessions import LocalProjectSessionAPI, ProjectSessionAPI
from .observability import ObservabilityService
from .adversarial import list_adversarial_cases, run_adversarial_campaign
from .recovery import (
    list_recovery_cases,
    run_recovery_campaign,
    sign_recovery_report,
    verify_recovery_report,
    write_recovery_evidence,
)
from .remote_worker import RemoteEndpoint, submit_remote_job
from .fleet import FleetRegistry
from .fleet_runner import execute_managed_fleet_job, probe_fleet_worker
from .release import verify_release_manifest
from .lab_certification import (
    build_certification_kit,
    certify_remote_windows_image,
    verify_certification_attestation,
    run_certification_campaign,
    verify_campaign_attestation,
)
from .ga import (
    evaluate_ga,
    run_key_rotation_drill,
    verify_ga_artifact_attestation,
    verify_ga_attestation,
    verify_ga_proof,
    write_ga_template,
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

SUPPORTED_PROTOCOLS = ("2026-07-28", "2025-11-25", "2025-06-18")
_MAX_MESSAGE_BYTES = 4 * 1024 * 1024


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        value["required"] = required
    return value


def _validate_schema(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise RepairError(f"{path} must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                raise RepairError(f"{path}.{name} is required")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise RepairError(f"{path} contains unknown properties: {', '.join(unknown)}")
        for name, item in value.items():
            child = properties.get(name)
            if isinstance(child, dict):
                _validate_schema(item, child, f"{path}.{name}")
        return
    if expected == "array":
        if not isinstance(value, list):
            raise RepairError(f"{path} must be an array")
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(value) < int(minimum):
            raise RepairError(f"{path} requires at least {minimum} item(s)")
        if maximum is not None and len(value) > int(maximum):
            raise RepairError(f"{path} permits at most {maximum} item(s)")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{index}]")
        return
    if expected == "string":
        if not isinstance(value, str):
            raise RepairError(f"{path} must be a string")
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and len(value) < int(minimum):
            raise RepairError(f"{path} is shorter than {minimum}")
        if maximum is not None and len(value) > int(maximum):
            raise RepairError(f"{path} is longer than {maximum}")
    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise RepairError(f"{path} must be an integer")
    elif expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RepairError(f"{path} must be a number")
    elif expected == "boolean":
        if not isinstance(value, bool):
            raise RepairError(f"{path} must be a boolean")
    if "enum" in schema and value not in schema["enum"]:
        raise RepairError(f"{path} must be one of: {', '.join(map(str, schema['enum']))}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if schema.get("minimum") is not None and value < schema["minimum"]:
            raise RepairError(f"{path} is below minimum {schema['minimum']}")
        if schema.get("maximum") is not None and value > schema["maximum"]:
            raise RepairError(f"{path} exceeds maximum {schema['maximum']}")


def tool_definitions() -> list[dict[str, Any]]:
    path_string = {"type": "string", "minLength": 1, "maxLength": 4096}
    short_string = {"type": "string", "maxLength": 512}
    tools = [
        {
            "name": "psmatrix_scan",
            "title": "Scan PowerShell files",
            "description": "Find .ps1, .psm1 and .psd1 files inside the configured project root.",
            "inputSchema": _object_schema({
                "path": {"type": "string", "default": ".", "maxLength": 4096},
            }),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_test",
            "title": "Test PowerShell sources",
            "description": "Run the mandatory PSMatrix parser, analyzer, execution and verification gate; issue a delivery receipt automatically on PASS.",
            "inputSchema": _object_schema({
                "paths": {"type": "array", "items": path_string, "minItems": 1, "maxItems": 64},
                "runtimes": {"type": "array", "items": short_string, "maxItems": 32},
                "matrix": short_string,
                "differential": {"type": "string", "enum": ["off", "report", "strict"], "default": "off"},
                "timeout": {"type": "number", "minimum": 1, "maximum": 900, "default": 60},
                "coverageFailUnder": {"type": "number", "minimum": 0, "maximum": 100},
            }, required=["paths"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_diagnose",
            "title": "Normalize diagnostics",
            "description": "Convert a PSMatrix report into stable diagnostic codes and a repair-oriented summary.",
            "inputSchema": _object_schema({"reportPath": path_string}, required=["reportPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_create_repair_plan",
            "title": "Create repair plan",
            "description": "Freeze report/source hashes and create a machine-readable repair plan.",
            "inputSchema": _object_schema({
                "reportPath": path_string,
                "validationArgv": {"type": "array", "items": {"type": "string", "maxLength": 16384}, "minItems": 2, "maxItems": 256},
                "outputPath": path_string,
            }, required=["reportPath", "validationArgv"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_propose_patch",
            "title": "Create minimal patch bundle",
            "description": "Turn exact old/new text replacements into a hash-bound minimal patch bundle without modifying files.",
            "inputSchema": _object_schema({
                "planPath": path_string,
                "files": {
                    "type": "array", "minItems": 1, "maxItems": 32,
                    "items": {
                        "type": "object", "additionalProperties": False,
                        "required": ["path", "edits"],
                        "properties": {
                            "path": path_string,
                            "before_sha256": {"type": "string", "maxLength": 64},
                            "edits": {
                                "type": "array", "minItems": 1, "maxItems": 256,
                                "items": {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["old", "new"],
                                    "properties": {
                                        "old": {"type": "string", "minLength": 1, "maxLength": 2097152},
                                        "new": {"type": "string", "maxLength": 2097152},
                                        "occurrence": {"type": "integer", "minimum": 1},
                                        "diagnostic_codes": {"type": "array", "items": short_string, "maxItems": 64},
                                        "reason": {"type": "string", "maxLength": 4096},
                                    },
                                },
                            },
                        },
                    },
                },
                "outputPath": path_string,
            }, required=["planPath", "files"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_apply_and_validate",
            "title": "Apply patch and validate",
            "description": "Apply a patch transaction, rerun the full requested test matrix, rollback on failure, and emit a signed delivery gate on PASS.",
            "inputSchema": _object_schema({
                "bundlePath": path_string,
                "validationArgv": {"type": "array", "items": {"type": "string", "maxLength": 16384}, "minItems": 2, "maxItems": 256},
                "sessionPath": path_string,
                "receiptPath": path_string,
                "maxAttempts": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
            }, required=["bundlePath", "validationArgv"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
        },
        {
            "name": "psmatrix_verify_gate",
            "title": "Verify delivery gate",
            "description": "Verify the signed test receipt and prove that validated source hashes are still current.",
            "inputSchema": _object_schema({"receiptPath": path_string}, required=["receiptPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_remote_test",
            "title": "Test on a trusted remote Windows worker",
            "description": "Submit a hash-bound, Ed25519-signed job over mTLS and accept the report only after worker signature, reset cycle, request hash, and TLS identity verification.",
            "inputSchema": _object_schema({
                "entrypoint": path_string,
                "endpointPath": path_string,
                "include": {"type": "array", "items": path_string, "maxItems": 128},
                "optionsPath": path_string,
                "reportPath": path_string,
                "timeout": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 1200},
            }, required=["entrypoint", "endpointPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_hybrid_test",
            "title": "Run a signed Linux and Windows mixed matrix",
            "description": "Run local PowerShell runtimes and one or more trusted remote Windows workers, then combine only verified reports.",
            "inputSchema": _object_schema({
                "entrypoint": path_string,
                "localRuntimes": {"type": "array", "items": short_string, "maxItems": 32},
                "localArgs": {"type": "array", "items": {"type": "string", "maxLength": 16384}, "maxItems": 128},
                "endpointPaths": {"type": "array", "items": path_string, "maxItems": 32},
                "include": {"type": "array", "items": path_string, "maxItems": 128},
                "remoteOptionsPath": path_string,
                "reportPath": path_string,
                "timeout": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 1200},
            }, required=["entrypoint"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_verify_attestation",
            "title": "Verify signed PSMatrix provenance",
            "description": "Verify a DSSE Ed25519 signature, in-toto/SLSA statement type, and optional evidence artifact digest.",
            "inputSchema": _object_schema({
                "attestationPath": path_string,
                "publicKeyPath": path_string,
                "artifactPath": path_string,
            }, required=["attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_fleet_health",
            "title": "Probe a managed Windows worker",
            "description": "Verify the enrolled worker's mTLS identity, signed health statement, exact authoritative runtime, and quarantine state.",
            "inputSchema": _object_schema({
                "workerId": short_string,
                "timeout": {"type": "integer", "minimum": 1, "maximum": 300, "default": 30},
                "quarantineThreshold": {"type": "integer", "minimum": 1, "maximum": 100, "default": 3},
            }, required=["workerId"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_fleet_test",
            "title": "Test on a managed Windows fleet worker",
            "description": "Select or address an enrolled authoritative Windows worker, prove snapshot reset before and after the job, and accept only a signed verified report.",
            "inputSchema": _object_schema({
                "entrypoint": path_string,
                "workerId": short_string,
                "runtimeId": short_string,
                "labels": {"type": "array", "items": {"type": "string", "minLength": 3, "maxLength": 320}, "maxItems": 32},
                "include": {"type": "array", "items": path_string, "maxItems": 128},
                "optionsPath": path_string,
                "reportPath": path_string,
                "timeout": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 1200},
                "quarantineThreshold": {"type": "integer", "minimum": 1, "maximum": 100, "default": 3},
            }, required=["entrypoint"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_verify_release",
            "title": "Verify a signed PSMatrix release",
            "description": "Verify every artifact size and SHA-256 digest in a release manifest and optionally require its Ed25519 DSSE signature.",
            "inputSchema": _object_schema({
                "manifestPath": path_string,
                "artifactDir": path_string,
                "publicKeyPath": path_string,
            }, required=["manifestPath", "artifactDir"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
    ]
    tools.extend([
        {
            "name": "psmatrix_lab_build_kit",
            "title": "Build Windows certification kit",
            "description": "Build a deterministic Windows PowerShell 4.0-5.1 image certification kit; optionally sign it with Ed25519/DSSE.",
            "inputSchema": _object_schema({
                "outputPath": path_string,
                "privateKeyPath": path_string,
                "publicKeyPath": path_string,
            }, required=["outputPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_certify",
            "title": "Certify a Windows PowerShell image",
            "description": "Run the read-only authoritative fixture pack on a trusted exact-version Windows worker with mandatory snapshot reset and emit a controller-signed certification attestation.",
            "inputSchema": _object_schema({
                "endpointPath": path_string,
                "imageManifestPath": path_string,
                "fixtureRoot": path_string,
                "privateKeyPath": path_string,
                "publicKeyPath": path_string,
                "outputPath": path_string,
                "timeout": {"type": "integer", "minimum": 30, "maximum": 3600, "default": 1800},
            }, required=["endpointPath", "imageManifestPath", "fixtureRoot", "privateKeyPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_lab_verify",
            "title": "Verify Windows image certification",
            "description": "Independently verify a DSSE-signed authoritative Windows image certification against the current manifest and fixture pack.",
            "inputSchema": _object_schema({
                "attestationPath": path_string,
                "publicKeyPath": path_string,
                "imageManifestPath": path_string,
                "fixtureRoot": path_string,
            }, required=["attestationPath", "publicKeyPath", "imageManifestPath", "fixtureRoot"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_campaign",
            "title": "Run Windows image certification campaign",
            "description": "Run repeated authoritative snapshot-reset certification cycles and emit a signed replay-resistant campaign summary.",
            "inputSchema": _object_schema({
                "endpointPath": path_string,
                "imageManifestPath": path_string,
                "fixtureRoot": path_string,
                "privateKeyPath": path_string,
                "publicKeyPath": path_string,
                "outputDir": path_string,
                "campaignOutputPath": path_string,
                "campaignId": {"type": "string", "minLength": 1, "maxLength": 128},
                "iterations": {"type": "integer", "minimum": 2, "maximum": 100, "default": 3},
                "timeout": {"type": "integer", "minimum": 30, "maximum": 3600, "default": 1800},
            }, required=["endpointPath", "imageManifestPath", "fixtureRoot", "privateKeyPath", "publicKeyPath", "outputDir", "campaignOutputPath", "campaignId"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_lab_verify_campaign",
            "title": "Verify Windows certification campaign",
            "description": "Verify every signed run, reject duplicate/replayed evidence, and validate the signed campaign summary.",
            "inputSchema": _object_schema({
                "campaignPath": path_string,
                "publicKeyPath": path_string,
                "imageManifestPath": path_string,
                "fixtureRoot": path_string,
                "attestationDir": path_string,
                "minimumRuns": {"type": "integer", "minimum": 2, "maximum": 1000, "default": 2},
            }, required=["campaignPath", "publicKeyPath", "imageManifestPath", "fixtureRoot", "attestationDir"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_profiles",
            "title": "List Windows lab profiles",
            "description": "List the exact Windows PowerShell 4.0, 5.0 and 5.1 golden-image profiles and WMF media requirements.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_plan",
            "title": "Build Hyper-V lab plan",
            "description": "Validate a SHA-256-bound Windows media manifest and create a secret-free Hyper-V provisioning plan.",
            "inputSchema": _object_schema({"manifestPath": path_string, "outputPath": path_string}, required=["manifestPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_build_provisioning_kit",
            "title": "Build Windows lab provisioning kit",
            "description": "Build a deterministic, optionally DSSE-signed Hyper-V provisioning kit with scripts, profiles and schemas.",
            "inputSchema": _object_schema({
                "outputPath": path_string, "planPath": path_string,
                "privateKeyPath": path_string, "publicKeyPath": path_string,
            }, required=["outputPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_verify_provisioning_kit",
            "title": "Verify Windows lab provisioning kit",
            "description": "Verify every declared file, digest and optional DSSE signature in a Hyper-V provisioning kit.",
            "inputSchema": _object_schema({"packagePath": path_string, "publicKeyPath": path_string}, required=["packagePath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_provision",
            "title": "Provision exact Windows PowerShell lab",
            "description": "Submit the immutable Hyper-V plan to a trusted Windows host worker and accept only hash-verified checkpointed 4.0/5.0/5.1 images.",
            "inputSchema": _object_schema({
                "endpointPath": path_string, "planPath": path_string, "reportPath": path_string,
                "timeout": {"type": "integer", "minimum": 600, "maximum": 21600, "default": 7200},
            }, required=["endpointPath", "planPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
        },
        {
            "name": "psmatrix_lab_authoritative_matrix",
            "title": "Run authoritative Windows matrix",
            "description": "Run repeated reset-bound certification campaigns on exact Windows PowerShell 4.0, 5.0 and 5.1 workers and emit one signed matrix attestation.",
            "inputSchema": _object_schema({
                "specPath": path_string, "outputDir": path_string, "matrixOutputPath": path_string,
                "privateKeyPath": path_string, "publicKeyPath": path_string,
                "releaseBindingPath": path_string,
                "timeout": {"type": "integer", "minimum": 30, "maximum": 3600, "default": 1800},
            }, required=["specPath", "outputDir", "matrixOutputPath", "privateKeyPath", "publicKeyPath", "releaseBindingPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_full_init",
            "title": "Create complete matrix specification",
            "description": "Write the canonical PowerShell 6.0-7.6 Linux plus authoritative Windows PowerShell 4.0/5.0/5.1 matrix specification.",
            "inputSchema": _object_schema({"outputPath": path_string}),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_full_plan",
            "title": "Plan complete mixed runtime matrix",
            "description": "Inspect native, OCI and trusted Windows-worker readiness without executing source code.",
            "inputSchema": _object_schema({"specPath": path_string, "outputPath": path_string}, required=["specPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_full_test",
            "title": "Run complete mixed runtime matrix",
            "description": "Run one source through all declared Linux native/OCI and authoritative Windows targets, enforce completeness, compare behavior and emit a structured report.",
            "inputSchema": _object_schema({
                "entrypoint": path_string,
                "specPath": path_string,
                "include": {"type": "array", "items": path_string, "maxItems": 128},
                "localArgs": {"type": "array", "items": {"type": "string", "maxLength": 16384}, "maxItems": 128},
                "remoteOptionsPath": path_string,
                "timeout": {"type": "integer", "minimum": 30, "maximum": 7200, "default": 1200},
                "jobs": {"type": "integer", "minimum": 0, "maximum": 64, "default": 0},
                "differential": {"type": "string", "enum": ["off", "report", "strict"]},
                "reportPath": path_string,
            }, required=["entrypoint", "specPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_adversarial_list",
            "title": "List defensive adversarial cases",
            "description": "List the built-in static-analysis, sandbox, resource, worker-trust and secret-handling cases.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_adversarial_run",
            "title": "Run defensive adversarial campaign",
            "description": "Run the bounded built-in attack corpus against the local sandbox and trust protocol; never treats an unavailable isolation primitive as PASS.",
            "inputSchema": _object_schema({
                "runtime": {"type": "string", "maxLength": 64, "default": "7.6.4"},
                "strict": {"type": "boolean", "default": False},
                "categories": {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 16},
                "reportPath": path_string,
            }),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_recovery_list",
            "title": "List recovery fault cases",
            "description": "List bounded controller, queue, database, transfer, snapshot, fleet and trust recovery scenarios.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_recovery_run",
            "title": "Run fault-tolerance recovery campaign",
            "description": "Inject bounded controller/queue/transfer/snapshot faults, prove recovery, and optionally emit deterministic evidence plus an Ed25519/DSSE attestation.",
            "inputSchema": _object_schema({
                "reportPath": path_string,
                "evidencePath": path_string,
                "attestationPath": path_string,
                "privateKeyPath": path_string,
                "publicKeyPath": path_string,
            }),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_recovery_verify",
            "title": "Verify signed recovery campaign",
            "description": "Independently verify the Ed25519/DSSE recovery attestation and its report binding.",
            "inputSchema": _object_schema({"attestationPath": path_string, "publicKeyPath": path_string}, required=["attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_mirror_verify",
            "title": "Verify offline module mirror",
            "description": "Verify the immutable module mirror index and every package SHA-256 before compatibility execution.",
            "inputSchema": _object_schema({"mirrorPath": path_string}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_compat_scan",
            "title": "Scan project module dependencies",
            "description": "Scan PowerShell project files for Import-Module, #requires, and RequiredModules declarations.",
            "inputSchema": _object_schema({"path": {"type": "string", "default": ".", "maxLength": 4096}, "outputPath": path_string}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_compat_plan",
            "title": "Plan module compatibility matrix",
            "description": "Check exact runtime and mirrored module availability; missing required combinations remain INCOMPLETE.",
            "inputSchema": _object_schema({"specPath": path_string, "mirrorPath": path_string, "outputPath": path_string}, required=["specPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_compat_run",
            "title": "Run module compatibility matrix",
            "description": "Install only SHA-verified mirrored modules, create exact locks, and run each project/runtime/tool combination through PSMatrix.",
            "inputSchema": _object_schema({"specPath": path_string, "mirrorPath": path_string, "outputPath": path_string, "timeout": {"type": "number", "minimum": 1, "maximum": 3600, "default": 120}}, required=["specPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_session_status",
            "title": "Inspect bounded project session",
            "description": "Report project file/byte quotas, expiry, and whether a current delivery gate exists.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_upload_text",
            "title": "Upload bounded project text",
            "description": "Create or replace one bounded UTF-8 PowerShell/project text file inside the current session root.",
            "inputSchema": _object_schema({
                "path": path_string,
                "text": {"type": "string", "maxLength": 2097152},
            }, required=["path", "text"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
        },
        {
            "name": "psmatrix_artifact_prepare",
            "title": "Prepare bounded artifact download",
            "description": "Issue a short-lived principal-bound artifact capability; delivery artifacts require a current PASS gate.",
            "inputSchema": _object_schema({
                "path": path_string,
                "purpose": {"type": "string", "enum": ["diagnostic", "delivery"]},
            }, required=["path", "purpose"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_delivery_status",
            "title": "Check delivery gate",
            "description": "Verify whether current project source hashes are covered by a valid PASS delivery receipt.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_bootstrap",
            "title": "Bootstrap exact runtime and module mirror",
            "description": "Install an exact hash-verified runtime and/or import an integrity-verified offline module mirror from uploaded project artifacts.",
            "inputSchema": _object_schema({
                "runtime": {"type": "string", "maxLength": 64},
                "runtimeArchivePath": path_string,
                "hashesPath": path_string,
                "mirrorArchivePath": path_string,
            }),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_web_validate",
            "title": "Run mandatory web delivery validation",
            "description": "Run module compatibility, the declared full runtime matrix, and the standard PSMatrix gate against the same project sources; HTTP delivery remains blocked unless every required stage passes and a hash-bound web receipt is recorded.",
            "inputSchema": _object_schema({
                "paths": {"type": "array", "items": path_string, "minItems": 1, "maxItems": 64},
                "runtimes": {"type": "array", "items": short_string, "minItems": 1, "maxItems": 32},
                "compatibilitySpecPath": path_string,
                "fullMatrixSpecPath": path_string,
                "mirrorPath": path_string,
                "include": {"type": "array", "items": path_string, "maxItems": 128},
                "localArgs": {"type": "array", "items": {"type": "string", "maxLength": 16384}, "maxItems": 128},
                "remoteOptionsPath": path_string,
                "timeout": {"type": "integer", "minimum": 30, "maximum": 7200, "default": 1200},
                "jobs": {"type": "integer", "minimum": 0, "maximum": 64, "default": 0},
                "differential": {"type": "string", "enum": ["off", "report", "strict"], "default": "strict"},
            }, required=["paths", "runtimes", "compatibilitySpecPath", "fullMatrixSpecPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_web_validation_status",
            "title": "Poll mandatory web delivery validation",
            "description": "Poll a bounded asynchronous web-validation job and finalize the hash-bound delivery receipt only after compatibility, full-matrix, and standard gate stages all pass.",
            "inputSchema": _object_schema({"jobId": short_string}, required=["jobId"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_lab_verify_authoritative_matrix",
            "title": "Verify authoritative Windows matrix",
            "description": "Independently verify the signed exact-runtime 4.0/5.0/5.1 matrix attestation.",
            "inputSchema": _object_schema({"attestationPath": path_string, "publicKeyPath": path_string}, required=["attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ops_snapshot",
            "title": "Read operations snapshot",
            "description": "Return a redacted read-only snapshot of runtimes, workers, queue, sessions, certificates, reports, mirror, cache, and alerts.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ops_audit_search",
            "title": "Search audit records",
            "description": "Search verified hash-chain audit records without returning credentials or raw source content.",
            "inputSchema": _object_schema({
                "action": {"type": "string", "maxLength": 128},
                "query": {"type": "string", "maxLength": 256},
                "since": {"type": "string", "maxLength": 64},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
            }),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ops_report_history",
            "title": "Read report history",
            "description": "List bounded report metadata and hashes; report bodies and source content are not returned.",
            "inputSchema": _object_schema({
                "status": {"type": "string", "maxLength": 64},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
            }),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ops_metrics",
            "title": "Read Prometheus metrics",
            "description": "Return the current Prometheus text exposition generated from the operations snapshot.",
            "inputSchema": _object_schema({}),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ops_support_bundle",
            "title": "Build redacted support bundle",
            "description": "Create a deterministic diagnostic-only ZIP with snapshot, metrics, audit summary, and report metadata; no source or credential bodies are included.",
            "inputSchema": _object_schema({"outputPath": path_string}),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ga_init",
            "title": "Initialize Production GA policy",
            "description": "Write the immutable mandatory 2.0.0 GA gate template; no required gate can be removed.",
            "inputSchema": _object_schema({"outputPath": path_string}),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ga_evaluate",
            "title": "Evaluate Production GA evidence",
            "description": "Verify every mandatory signed Production GA evidence gate and return PASS, FAIL, or INCOMPLETE without weakening missing evidence.",
            "inputSchema": _object_schema({"policyPath": path_string, "outputPath": path_string}, required=["policyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ga_verify_proof",
            "title": "Verify external GA proof",
            "description": "Verify a role-signed public deployment, OTLP, key rotation, security review, or vulnerability proof.",
            "inputSchema": _object_schema({
                "type": {"type": "string", "enum": ["public-oauth", "public-mtls", "external-otlp", "key-rotation", "security-review", "vulnerability-scan"]},
                "attestationPath": path_string,
                "publicKeyPath": path_string,
            }, required=["type", "attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ga_verify_artifact",
            "title": "Verify CI-signed GA artifact",
            "description": "Verify digest binding for a CI-signed validation summary or complete full-matrix report.",
            "inputSchema": _object_schema({
                "type": {"type": "string", "enum": ["validation-summary", "full-matrix-report"]},
                "artifactPath": path_string,
                "attestationPath": path_string,
                "publicKeyPath": path_string,
            }, required=["type", "artifactPath", "attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        {
            "name": "psmatrix_ga_key_rotation_drill",
            "title": "Run key rotation and revocation drill",
            "description": "Run a bounded isolated Ed25519 rotation/revocation drill and emit signed evidence.",
            "inputSchema": _object_schema({"privateKeyPath": path_string, "publicKeyPath": path_string, "outputPath": path_string}, required=["privateKeyPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        },
        {
            "name": "psmatrix_ga_verify_attestation",
            "title": "Verify final Production GA attestation",
            "description": "Verify that the signed 2.0.0 GA attestation contains all eleven mandatory PASS gates.",
            "inputSchema": _object_schema({"attestationPath": path_string, "publicKeyPath": path_string}, required=["attestationPath", "publicKeyPath"]),
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
    ])
    return sorted(tools, key=lambda value: value["name"])


class MCPServer:
    def __init__(self, root: Path, home: Path, *, session_api: ProjectSessionAPI | None = None) -> None:
        self.root = root.resolve()
        self.home = home.resolve()
        self.session_api = session_api or LocalProjectSessionAPI(self.root, self.home)
        self.work = self.root / ".psmatrix" / "mcp"
        self.work.mkdir(parents=True, exist_ok=True)
        self.negotiated = False
        self.initialized = False
        self.protocol = "2025-11-25"
        self._web_validation_results: dict[str, dict[str, Any]] = {}
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "psmatrix_scan": self._scan,
            "psmatrix_test": self._test,
            "psmatrix_diagnose": self._diagnose,
            "psmatrix_create_repair_plan": self._create_plan,
            "psmatrix_propose_patch": self._propose_patch,
            "psmatrix_apply_and_validate": self._apply_and_validate,
            "psmatrix_verify_gate": self._verify_gate,
            "psmatrix_remote_test": self._remote_test,
            "psmatrix_hybrid_test": self._hybrid_test,
            "psmatrix_verify_attestation": self._verify_attestation,
            "psmatrix_fleet_health": self._fleet_health,
            "psmatrix_fleet_test": self._fleet_test,
            "psmatrix_verify_release": self._verify_release,
            "psmatrix_lab_build_kit": self._lab_build_kit,
            "psmatrix_lab_certify": self._lab_certify,
            "psmatrix_lab_verify": self._lab_verify,
            "psmatrix_lab_campaign": self._lab_campaign,
            "psmatrix_lab_verify_campaign": self._lab_verify_campaign,
            "psmatrix_lab_profiles": self._lab_profiles,
            "psmatrix_lab_plan": self._lab_plan,
            "psmatrix_lab_build_provisioning_kit": self._lab_build_provisioning_kit,
            "psmatrix_lab_verify_provisioning_kit": self._lab_verify_provisioning_kit,
            "psmatrix_lab_provision": self._lab_provision,
            "psmatrix_lab_authoritative_matrix": self._lab_authoritative_matrix,
            "psmatrix_lab_verify_authoritative_matrix": self._lab_verify_authoritative_matrix,
            "psmatrix_full_init": self._full_init,
            "psmatrix_full_plan": self._full_plan,
            "psmatrix_full_test": self._full_test,
            "psmatrix_adversarial_list": self._adversarial_list,
            "psmatrix_adversarial_run": self._adversarial_run,
            "psmatrix_recovery_list": self._recovery_list,
            "psmatrix_recovery_run": self._recovery_run,
            "psmatrix_recovery_verify": self._recovery_verify,
            "psmatrix_mirror_verify": self._mirror_verify,
            "psmatrix_compat_scan": self._compat_scan,
            "psmatrix_compat_plan": self._compat_plan,
            "psmatrix_compat_run": self._compat_run,
            "psmatrix_session_status": self._session_status,
            "psmatrix_upload_text": self._upload_text,
            "psmatrix_artifact_prepare": self._artifact_prepare,
            "psmatrix_delivery_status": self._delivery_status,
            "psmatrix_bootstrap": self._bootstrap,
            "psmatrix_web_validate": self._web_validate,
            "psmatrix_web_validation_status": self._web_validation_status,
            "psmatrix_ops_snapshot": self._ops_snapshot,
            "psmatrix_ops_audit_search": self._ops_audit_search,
            "psmatrix_ops_report_history": self._ops_report_history,
            "psmatrix_ops_metrics": self._ops_metrics,
            "psmatrix_ops_support_bundle": self._ops_support_bundle,
            "psmatrix_ga_init": self._ga_init,
            "psmatrix_ga_evaluate": self._ga_evaluate,
            "psmatrix_ga_verify_proof": self._ga_verify_proof,
            "psmatrix_ga_verify_artifact": self._ga_verify_artifact,
            "psmatrix_ga_key_rotation_drill": self._ga_key_rotation_drill,
            "psmatrix_ga_verify_attestation": self._ga_verify_attestation,
        }

    def _project_path(self, value: str, *, must_exist: bool = True) -> Path:
        return resolve_project_file(self.root, value, must_exist=must_exist)

    def _project_directory(self, value: str) -> Path:
        candidate = (self.root / value).resolve()
        if self.root not in candidate.parents and candidate != self.root:
            raise RepairError(f"MCP directory escapes project root: {value}")
        cursor = self.root
        for part in candidate.relative_to(self.root).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RepairError(f"MCP directory cannot traverse symlinks: {value}")
        if not candidate.is_dir():
            raise RepairError(f"MCP directory does not exist: {value}")
        return candidate

    def _output_path(self, value: str | None, default_name: str) -> Path:
        path = self.work / default_name if not value else (self.root / value)
        resolved = path.resolve()
        if self.root not in resolved.parents and resolved != self.root:
            raise RepairError(f"MCP output path escapes project root: {value}")
        cursor = self.root
        for part in resolved.relative_to(self.root).parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RepairError(f"MCP output parent cannot be a symlink: {value}")
        return resolved

    def _adversarial_list(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"cases": list_adversarial_cases(), "count": len(list_adversarial_cases())}

    def _adversarial_run(self, args: dict[str, Any]) -> dict[str, Any]:
        report_path = self._output_path(args.get("reportPath"), f"adversarial-{utc_now_iso().replace(':', '-')}.json")
        report = run_adversarial_campaign(
            home=self.home,
            runtime_version=str(args.get("runtime") or "7.6.4"),
            strict=bool(args.get("strict", False)),
            categories=set(str(value) for value in (args.get("categories") or [])) or None,
            output=report_path,
        )
        return {
            "status": report.status,
            "summary": report.summary,
            "reportPath": report_path.relative_to(self.root).as_posix(),
            "capabilities": report.capabilities,
        }

    def _recovery_list(self, args: dict[str, Any]) -> dict[str, Any]:
        cases = list_recovery_cases()
        return {"cases": cases, "count": len(cases)}

    def _recovery_run(self, args: dict[str, Any]) -> dict[str, Any]:
        private = self._project_path(str(args["privateKeyPath"])) if args.get("privateKeyPath") else None
        public = self._project_path(str(args["publicKeyPath"])) if args.get("publicKeyPath") else None
        if (private is None) != (public is None):
            raise RepairError("Recovery signing requires both privateKeyPath and publicKeyPath")
        if args.get("attestationPath") and private is None:
            raise RepairError("Recovery attestation requires signing keys")
        report = run_recovery_campaign(self.home, private_key=private, public_key=public)
        report_path = self._output_path(args.get("reportPath"), f"recovery-{utc_now_iso().replace(':', '-')}.json")
        atomic_write_json(report_path, report)
        evidence_path = None
        if args.get("evidencePath"):
            evidence = self._output_path(str(args["evidencePath"]), "recovery-evidence.zip")
            write_recovery_evidence(report, evidence)
            evidence_path = evidence.relative_to(self.root).as_posix()
        attestation_path = None
        if args.get("attestationPath"):
            attestation = self._output_path(str(args["attestationPath"]), "recovery.dsse.json")
            atomic_write_json(attestation, sign_recovery_report(report, private, public))
            attestation_path = attestation.relative_to(self.root).as_posix()
        return {
            "status": report["status"],
            "summary": report["summary"],
            "reportPath": report_path.relative_to(self.root).as_posix(),
            "evidencePath": evidence_path,
            "attestationPath": attestation_path,
        }

    def _recovery_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        attestation = read_json(self._project_path(str(args["attestationPath"])))
        public = self._project_path(str(args["publicKeyPath"]))
        return verify_recovery_report(attestation, public)

    def _ops_service(self) -> ObservabilityService:
        record = getattr(self.session_api, "record", None)
        if record is not None and getattr(record, "session_id", "stdio") != "stdio":
            try:
                global_home = Path(record.root).resolve().parents[2]
            except IndexError:
                global_home = self.home
            return ObservabilityService(global_home, session_store=getattr(self.session_api, "store", None))
        return ObservabilityService(self.home, session_store=getattr(self.session_api, "store", None))

    def _ops_snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._ops_service().snapshot()
        value["current_session"] = self.session_api.status()
        return value

    def _ops_audit_search(self, args: dict[str, Any]) -> dict[str, Any]:
        record = getattr(self.session_api, "record", None)
        session_id = None if record is None or getattr(record, "session_id", "stdio") == "stdio" else str(record.session_id)
        return self._ops_service().audit_search(
            action=str(args.get("action") or "") or None,
            query=str(args.get("query") or "") or None,
            since=str(args.get("since") or "") or None,
            session_id=session_id,
            limit=int(args.get("limit") or 200),
        )

    def _ops_report_history(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._ops_service().report_history(
            status=str(args.get("status") or "") or None,
            limit=int(args.get("limit") or 200),
            root=self.root,
        )

    def _ops_metrics(self, args: dict[str, Any]) -> dict[str, Any]:
        text = self._ops_service().prometheus()
        return {"contentType": "text/plain; version=0.0.4", "text": text, "bytes": len(text.encode("utf-8"))}

    def _ops_support_bundle(self, args: dict[str, Any]) -> dict[str, Any]:
        output = self._output_path(args.get("outputPath"), "support-bundle.zip")
        result = self._ops_service().build_support_bundle(output)
        return {**result, "path": output.relative_to(self.root).as_posix(), "purpose": "diagnostic"}

    def _ga_init(self, args: dict[str, Any]) -> dict[str, Any]:
        output = self._output_path(args.get("outputPath"), "ga-policy.json")
        return write_ga_template(output)

    def _ga_evaluate(self, args: dict[str, Any]) -> dict[str, Any]:
        policy = self._project_path(str(args.get("policyPath") or ""))
        output = self._output_path(str(args["outputPath"]), "ga-evaluation.json") if args.get("outputPath") else None
        return evaluate_ga(policy, output=output).to_dict()

    def _ga_verify_proof(self, args: dict[str, Any]) -> dict[str, Any]:
        envelope = read_json(self._project_path(str(args.get("attestationPath") or "")))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        return verify_ga_proof(envelope, public_key=public_key, expected_type=str(args.get("type") or ""))

    def _ga_verify_artifact(self, args: dict[str, Any]) -> dict[str, Any]:
        artifact = self._project_path(str(args.get("artifactPath") or ""))
        envelope = read_json(self._project_path(str(args.get("attestationPath") or "")))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        return verify_ga_artifact_attestation(
            envelope, artifact=artifact, artifact_type=str(args.get("type") or ""), public_key=public_key,
        )

    def _ga_key_rotation_drill(self, args: dict[str, Any]) -> dict[str, Any]:
        private_key = self._project_path(str(args.get("privateKeyPath") or ""))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        output = self._output_path(args.get("outputPath"), "ga-key-rotation.dsse.json")
        envelope = run_key_rotation_drill(signing_private_key=private_key, signing_public_key=public_key)
        atomic_write_json(output, envelope)
        return {"valid": True, "path": output.relative_to(self.root).as_posix()}

    def _ga_verify_attestation(self, args: dict[str, Any]) -> dict[str, Any]:
        envelope = read_json(self._project_path(str(args.get("attestationPath") or "")))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        return verify_ga_attestation(envelope, public_key=public_key)

    def _session_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.session_api.status()

    def _upload_text(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.session_api.upload_text(str(args.get("path") or ""), str(args.get("text") or ""))

    def _artifact_prepare(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.session_api.prepare_artifact(str(args.get("path") or ""), str(args.get("purpose") or ""))

    def _delivery_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.session_api.delivery_status()

    def _bootstrap(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.session_api.bootstrap(
            runtime=str(args["runtime"]) if args.get("runtime") else None,
            runtime_archive=str(args["runtimeArchivePath"]) if args.get("runtimeArchivePath") else None,
            hashes_file=str(args["hashesPath"]) if args.get("hashesPath") else None,
            mirror_archive=str(args["mirrorArchivePath"]) if args.get("mirrorArchivePath") else None,
        )

    def _finalize_web_validation(self, job_id: str, result: dict[str, Any]) -> dict[str, Any]:
        cached = self._web_validation_results.get(job_id)
        if cached is not None:
            return cached
        status = str(result.get("status") or "FAIL_CONTROLLER")
        if status != "PASS":
            value = {
                "status": status,
                "jobId": job_id,
                "stage": str(result.get("stage") or "controller"),
                "compatibilityReportPath": result.get("compatibility_report"),
                "fullMatrixReportPath": result.get("full_matrix_report"),
                "standardReportPath": result.get("standard_report"),
                "error": result.get("error") or result.get("stderr_tail"),
                "deliveryReady": False,
            }
            self._web_validation_results[job_id] = value
            return value
        sources = result.get("sources")
        reports = result.get("reports")
        gate = str(result.get("gate_receipt") or "")
        if not isinstance(sources, list) or not sources or not isinstance(reports, list) or len(reports) < 3 or not gate:
            raise RepairError("Completed web validation result is missing source/report/gate bindings")
        web_receipt = self.session_api.record_web_validation({
            "status": "PASS",
            "sources": [str(item) for item in sources],
            "reports": [str(item) for item in reports],
            "gate_receipt_path": gate,
        })
        delivery = self.session_api.delivery_status()
        if not delivery.get("ready"):
            raise RepairError("Web validation receipt was created but delivery gate is not ready")
        value = {
            "status": "PASS",
            "jobId": job_id,
            "stage": "complete",
            "compatibilityReportPath": result.get("compatibility_report"),
            "fullMatrixReportPath": result.get("full_matrix_report"),
            "standardReportPath": result.get("standard_report"),
            "receiptPath": gate,
            "webValidationReceiptPath": web_receipt["path"],
            "webValidationSha256": web_receipt["sha256"],
            "deliveryReady": True,
        }
        self._web_validation_results[job_id] = value
        return value

    def _web_validate(self, args: dict[str, Any]) -> dict[str, Any]:
        paths_raw = args.get("paths")
        runtimes_raw = args.get("runtimes")
        if not isinstance(paths_raw, list) or not paths_raw:
            raise RepairError("paths must be a non-empty array")
        if not isinstance(runtimes_raw, list) or not runtimes_raw:
            raise RepairError("runtimes must be a non-empty array")
        source_paths = [self._project_path(str(value)) for value in paths_raw]
        include = [self._project_path(str(value)) for value in (args.get("include") or [])]
        all_sources = list(dict.fromkeys([*source_paths, *include]))
        timeout = int(args.get("timeout") or 1200)
        jobs = int(args.get("jobs") or 0)
        differential = str(args.get("differential") or "strict")

        compatibility_path = self._output_path(None, "web-compatibility.json")
        full_path = self._output_path(None, "web-full-matrix.json")
        standard_path = self._output_path(None, "web-standard-report.json")
        gate_path = self._output_path(None, "gate-web-standard.json")
        stage_request_path = self._output_path(None, "web-validation-request.json")
        remote_options: dict[str, Any] = {}
        if args.get("remoteOptionsPath"):
            value = read_json(self._project_path(str(args["remoteOptionsPath"])))
            if not isinstance(value, dict):
                raise RepairError("Full matrix remote options root must be an object")
            remote_options = value
        request = {
            "schema": 1,
            "root": str(self.root),
            "home": str(self.home),
            "entrypoint": source_paths[0].relative_to(self.root).as_posix(),
            "sources": [path.relative_to(self.root).as_posix() for path in all_sources],
            "runtimes": [str(item) for item in runtimes_raw],
            "include": [path.relative_to(self.root).as_posix() for path in include],
            "compatibility_spec": self._project_path(str(args.get("compatibilitySpecPath") or "")).relative_to(self.root).as_posix(),
            "full_spec": self._project_path(str(args.get("fullMatrixSpecPath") or "")).relative_to(self.root).as_posix(),
            "compatibility_output": compatibility_path.relative_to(self.root).as_posix(),
            "full_output": full_path.relative_to(self.root).as_posix(),
            "standard_output": standard_path.relative_to(self.root).as_posix(),
            "gate_output": gate_path.relative_to(self.root).as_posix(),
            "mirror_root": str(self._mirror_root(args.get("mirrorPath"))),
            "local_args": [str(item) for item in (args.get("localArgs") or [])],
            "remote_options": remote_options,
            "timeout": timeout,
            "jobs": jobs,
            "differential": differential,
        }
        atomic_write_json(stage_request_path, request)
        submitted = self.session_api.submit_web_validation(request)
        if submitted.get("status") == "COMPLETE":
            return self._finalize_web_validation(str(submitted.get("jobId") or "stdio"), submitted.get("result") or {})
        return {
            "status": "RUNNING",
            "jobId": str(submitted.get("jobId") or ""),
            "stage": "queued",
            "deliveryReady": False,
        }

    def _web_validation_status(self, args: dict[str, Any]) -> dict[str, Any]:
        job_id = str(args.get("jobId") or "")
        cached = self._web_validation_results.get(job_id)
        if cached is not None:
            return cached
        status = self.session_api.web_validation_status(job_id)
        if status.get("status") != "COMPLETE":
            return {"status": "RUNNING", "jobId": job_id, "stage": "executing", "deliveryReady": False}
        result = status.get("result")
        if not isinstance(result, dict):
            raise RepairError("Web validation job result is malformed")
        return self._finalize_web_validation(job_id, result)

    def _mirror_root(self, value: str | None) -> Path:
        if value:
            candidate = (self.root / value).resolve()
            if self.root not in candidate.parents and candidate != self.root:
                raise RepairError("Mirror path escapes project root")
            return candidate
        return self.home / "module-mirror"

    def _mirror_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        return OfflineModuleMirror(self._mirror_root(args.get("mirrorPath"))).verify()

    def _compat_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        path_value = str(args.get("path") or ".")
        path = self._project_directory(path_value) if (self.root / path_value).resolve().is_dir() else self._project_path(path_value)
        result = scan_project_dependencies(path)
        if args.get("outputPath"):
            atomic_write_json(self._output_path(str(args["outputPath"]), "compat-scan.json"), result)
        return result

    def _compat_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        spec = self._project_path(str(args["specPath"]))
        result = plan_compatibility_matrix(spec, mirror_root=self._mirror_root(args.get("mirrorPath")), runtime_home=self.home)
        if args.get("outputPath"):
            atomic_write_json(self._output_path(str(args["outputPath"]), "compat-plan.json"), result)
        return result

    def _compat_run(self, args: dict[str, Any]) -> dict[str, Any]:
        spec = self._project_path(str(args["specPath"]))
        output = self._output_path(args.get("outputPath"), "compat-report.json")
        return execute_compatibility_matrix(
            spec,
            mirror_root=self._mirror_root(args.get("mirrorPath")),
            home=self.home,
            output=output,
            timeout=float(args.get("timeout") or 120),
        )

    def _scan(self, args: dict[str, Any]) -> dict[str, Any]:
        path_value = str(args.get("path") or ".")
        candidate = self.root if path_value == "." else (self.root / path_value)
        path = candidate.resolve()
        if self.root not in path.parents and path != self.root:
            raise RepairError(f"Scan path escapes project root: {path_value}")
        cursor = self.root
        for part in path.relative_to(self.root).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RepairError(f"Scan path cannot traverse symlinks: {path_value}")
        if not path.exists():
            raise RepairError(f"Scan path does not exist: {path_value}")
        files = scan_powershell_files(path)
        return {"files": [item.relative_to(self.root).as_posix() for item in files], "count": len(files)}

    def _test(self, args: dict[str, Any]) -> dict[str, Any]:
        paths = args.get("paths")
        if not isinstance(paths, list) or not paths:
            raise RepairError("paths must be a non-empty array")
        argv = ["test"]
        for value in paths:
            path = self._project_path(str(value))
            argv.append(path.relative_to(self.root).as_posix())
        runtimes = args.get("runtimes") or []
        if not isinstance(runtimes, list):
            raise RepairError("runtimes must be an array")
        for value in runtimes:
            argv.extend(["--runtime", str(value)])
        matrix = args.get("matrix")
        if matrix:
            argv.extend(["--matrix", str(matrix)])
        argv.extend(["--differential", str(args.get("differential") or "off")])
        argv.extend(["--timeout", str(float(args.get("timeout") or 60))])
        if args.get("coverageFailUnder") is not None:
            argv.extend(["--coverage-fail-under", str(float(args["coverageFailUnder"]))])
        argv.extend(["--network", "none", "--sandbox", "auto"])
        report_path = self.work / f"test-{utc_now_iso().replace(':', '-')}.json"
        exit_code, report, _stdout, stderr = run_validation(self.root, self.home, argv, report_path)
        diagnostics, summary = report_diagnostics(report)
        receipt_path = None
        if report.get("status") == "PASS":
            receipt = create_gate_receipt(report, self.root, self.home)
            receipt_file = self.work / f"gate-{report_path.stem}.json"
            write_gate_receipt(receipt_file, receipt)
            receipt_path = receipt_file.relative_to(self.root).as_posix()
        return {
            "exitCode": exit_code,
            "status": report.get("status"),
            "reportPath": report_path.relative_to(self.root).as_posix(),
            "receiptPath": receipt_path,
            "diagnosticSummary": summary,
            "diagnostics": diagnostics[:200],
            "stderrTail": stderr[-2048:],
        }

    def _diagnose(self, args: dict[str, Any]) -> dict[str, Any]:
        report_path = self._project_path(str(args.get("reportPath") or ""))
        report = read_json(report_path)
        diagnostics, summary = report_diagnostics(report)
        return {"summary": summary, "diagnostics": diagnostics}

    def _create_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        report_path = self._project_path(str(args.get("reportPath") or ""))
        report = read_json(report_path)
        validation = args.get("validationArgv")
        if not isinstance(validation, list):
            raise RepairError("validationArgv must be an array")
        plan = build_repair_plan(report, self.root, validation_argv=[str(value) for value in validation])
        output = self._output_path(args.get("outputPath"), f"{plan['plan_id']}.json")
        atomic_write_json(output, plan)
        return {"planPath": output.relative_to(self.root).as_posix(), "plan": plan}

    def _propose_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        plan_path = self._project_path(str(args.get("planPath") or ""))
        plan = read_json(plan_path)
        proposal = {"files": args.get("files")}
        bundle = propose_patch(self.root, proposal, plan=plan)
        output = self._output_path(args.get("outputPath"), f"{bundle['bundle_id']}.json")
        atomic_write_json(output, bundle)
        return {"bundlePath": output.relative_to(self.root).as_posix(), "bundle": bundle}

    def _apply_and_validate(self, args: dict[str, Any]) -> dict[str, Any]:
        bundle_path = self._project_path(str(args.get("bundlePath") or ""))
        bundle = read_json(bundle_path)
        validation = args.get("validationArgv")
        if not isinstance(validation, list):
            raise RepairError("validationArgv must be an array")
        session_path = self._output_path(args.get("sessionPath"), "repair-session.json")
        result = apply_and_validate(
            self.root, self.home, bundle, [str(value) for value in validation],
            session_path=session_path, max_attempts=int(args.get("maxAttempts") or 3),
        )
        receipt_path = None
        if result["accepted"]:
            receipt = create_gate_receipt(
                result["report"], self.root, self.home,
                transaction_id=result["attempt"].get("transaction_id"),
            )
            path = self._output_path(args.get("receiptPath"), "delivery-gate.json")
            write_gate_receipt(path, receipt)
            receipt_path = path.relative_to(self.root).as_posix()
        return {
            "accepted": result["accepted"],
            "sessionPath": session_path.relative_to(self.root).as_posix(),
            "receiptPath": receipt_path,
            "attempt": result["attempt"],
            "status": result["report"].get("status") if result["report"] else None,
        }

    def _verify_gate(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._project_path(str(args.get("receiptPath") or ""))
        return verify_gate_receipt(load_gate_receipt(path), self.root, self.home)

    def _remote_test(self, args: dict[str, Any]) -> dict[str, Any]:
        entrypoint = self._project_path(str(args.get("entrypoint") or ""))
        endpoint_path = self._project_path(str(args.get("endpointPath") or ""))
        include = [self._project_path(str(value)) for value in (args.get("include") or [])]
        options: dict[str, Any] = {}
        if args.get("optionsPath"):
            value = read_json(self._project_path(str(args["optionsPath"])))
            if not isinstance(value, dict):
                raise RepairError("Remote options root must be an object")
            options = value
        endpoint = RemoteEndpoint.load(endpoint_path, trust_home=self.home)
        verified = submit_remote_job(
            endpoint, root=self.root, files=[entrypoint, *include], entrypoint=entrypoint,
            options=options, timeout=int(args.get("timeout") or 1200),
        )
        report_path = self._output_path(args.get("reportPath"), f"remote-{endpoint.worker_id}-{utc_now_iso().replace(':', '-')}.json")
        atomic_write_json(report_path, verified["report"])
        return {
            "status": verified["report"].get("status"),
            "workerId": endpoint.worker_id,
            "signatureValid": True,
            "reset": verified["reset"],
            "capabilities": verified["capabilities"],
            "reportPath": report_path.relative_to(self.root).as_posix(),
        }

    def _hybrid_test(self, args: dict[str, Any]) -> dict[str, Any]:
        entrypoint = self._project_path(str(args.get("entrypoint") or ""))
        endpoint_paths = [self._project_path(str(value)) for value in (args.get("endpointPaths") or [])]
        include = [self._project_path(str(value)) for value in (args.get("include") or [])]
        remote_options: dict[str, Any] = {}
        if args.get("remoteOptionsPath"):
            value = read_json(self._project_path(str(args["remoteOptionsPath"])))
            if not isinstance(value, dict):
                raise RepairError("Hybrid remote options root must be an object")
            remote_options = value
        report = execute_hybrid_matrix(
            home=self.home, root=self.root, entrypoint=entrypoint,
            local_runtimes=[str(value) for value in (args.get("localRuntimes") or [])],
            local_args=[str(value) for value in (args.get("localArgs") or [])],
            endpoint_paths=endpoint_paths, include=include, remote_options=remote_options,
            timeout=int(args.get("timeout") or 1200),
        )
        report_path = self._output_path(args.get("reportPath"), f"hybrid-{utc_now_iso().replace(':', '-')}.json")
        atomic_write_json(report_path, report)
        return {
            "status": report.get("status"),
            "targetCount": len(report.get("targets", [])),
            "reportPath": report_path.relative_to(self.root).as_posix(),
            "matrix": report.get("matrix"),
        }

    def _verify_attestation(self, args: dict[str, Any]) -> dict[str, Any]:
        attestation = self._project_path(str(args.get("attestationPath") or ""))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        artifact = self._project_path(str(args["artifactPath"])) if args.get("artifactPath") else None
        result = verify_provenance(load_attestation(attestation), public_key, artifact=artifact)
        return {
            "valid": result["valid"],
            "keyIds": result["key_ids"],
            "artifactValid": result["artifact_valid"],
            "subject": result["statement"].get("subject"),
            "builder": result["statement"].get("predicate", {}).get("runDetails", {}).get("builder"),
        }

    @staticmethod
    def _label_arguments(values: list[Any]) -> dict[str, str]:
        labels: dict[str, str] = {}
        for raw in values:
            text = str(raw)
            if "=" not in text:
                raise RepairError("Fleet labels must use KEY=VALUE form")
            name, value = text.split("=", 1)
            if not name or not value:
                raise RepairError("Fleet labels must use non-empty KEY=VALUE form")
            if name in labels:
                raise RepairError(f"Duplicate fleet label: {name}")
            labels[name] = value
        return labels

    def _fleet_health(self, args: dict[str, Any]) -> dict[str, Any]:
        worker_id = str(args.get("workerId") or "")
        registry = FleetRegistry(self.home)
        health = probe_fleet_worker(
            registry,
            worker_id,
            timeout=int(args.get("timeout") or 30),
            quarantine_threshold=int(args.get("quarantineThreshold") or 3),
        )
        record = registry.get(worker_id)
        return {
            "workerId": worker_id,
            "state": record.get("state"),
            "runtimeId": health.get("runtime_id"),
            "authoritative": health.get("authoritative"),
            "capabilities": health.get("capabilities"),
            "signatureValid": True,
        }

    def _fleet_test(self, args: dict[str, Any]) -> dict[str, Any]:
        entrypoint = self._project_path(str(args.get("entrypoint") or ""))
        include = [self._project_path(str(value)) for value in (args.get("include") or [])]
        options: dict[str, Any] = {}
        if args.get("optionsPath"):
            loaded = read_json(self._project_path(str(args["optionsPath"])))
            if not isinstance(loaded, dict):
                raise RepairError("Fleet options root must be an object")
            options = loaded
        registry = FleetRegistry(self.home)
        worker_id = str(args.get("workerId") or "")
        if not worker_id:
            runtime_id = str(args.get("runtimeId") or "")
            if not runtime_id:
                raise RepairError("fleet_test requires workerId or runtimeId")
            labels = self._label_arguments(list(args.get("labels") or []))
            selection = registry.select(runtime_id, labels=labels, count=1)
            if not selection:
                raise RepairError(f"No active healthy worker satisfies runtime {runtime_id}")
            worker_id = selection[0].worker_id
        result = execute_managed_fleet_job(
            registry,
            worker_id=worker_id,
            root=self.root,
            files=[entrypoint, *include],
            entrypoint=entrypoint,
            options=options,
            timeout=int(args.get("timeout") or 1200),
            quarantine_threshold=int(args.get("quarantineThreshold") or 3),
        )
        report_path = self._output_path(args.get("reportPath"), f"fleet-{worker_id}-{utc_now_iso().replace(':', '-')}.json")
        atomic_write_json(report_path, result)
        return {
            "status": result.get("status"),
            "workerId": worker_id,
            "runtimeId": result.get("runtime_id"),
            "snapshotResetValid": bool(
                result.get("snapshot_reset", {}).get("before", {}).get("verification", {}).get("valid")
                and result.get("snapshot_reset", {}).get("after", {}).get("verification", {}).get("valid")
            ),
            "workerResultValid": bool(result.get("worker_result", {}).get("valid")),
            "reportPath": report_path.relative_to(self.root).as_posix(),
        }

    def _verify_release(self, args: dict[str, Any]) -> dict[str, Any]:
        manifest = self._project_path(str(args.get("manifestPath") or ""))
        artifact_dir = self._project_directory(str(args.get("artifactDir") or "."))
        public_key = self._project_path(str(args["publicKeyPath"])) if args.get("publicKeyPath") else None
        result = verify_release_manifest(manifest, artifact_dir, signing_public_key=public_key)
        return {
            "valid": result.get("valid"),
            "version": result.get("version"),
            "artifacts": result.get("artifacts"),
            "signature": result.get("signature"),
        }

    def _lab_build_kit(self, args: dict[str, Any]) -> dict[str, Any]:
        output = self._output_path(str(args.get("outputPath") or ""), "windows-certification-kit.zip")
        private_key = self._project_path(str(args["privateKeyPath"])) if args.get("privateKeyPath") else None
        public_key = self._project_path(str(args["publicKeyPath"])) if args.get("publicKeyPath") else None
        return build_certification_kit(
            self.root, output, version=__version__,
            signing_private_key=private_key, signing_public_key=public_key,
        )

    def _lab_certify(self, args: dict[str, Any]) -> dict[str, Any]:
        endpoint_path = self._project_path(str(args.get("endpointPath") or ""))
        image_manifest = self._project_path(str(args.get("imageManifestPath") or ""))
        fixture_root = self._project_directory(str(args.get("fixtureRoot") or ""))
        private_key = self._project_path(str(args.get("privateKeyPath") or ""))
        public_key = self._project_path(str(args.get("publicKeyPath") or ""))
        output = self._output_path(args.get("outputPath"), "windows-image-certification.dsse.json")
        endpoint = RemoteEndpoint.load(endpoint_path, trust_home=self.home)
        return certify_remote_windows_image(
            endpoint=endpoint, image_manifest=image_manifest, fixture_root=fixture_root, output=output,
            private_key=private_key, public_key=public_key, timeout=int(args.get("timeout") or 1800),
        )

    def _lab_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        return verify_certification_attestation(
            self._project_path(str(args.get("attestationPath") or "")),
            public_key=self._project_path(str(args.get("publicKeyPath") or "")),
            image_manifest=self._project_path(str(args.get("imageManifestPath") or "")),
            fixture_root=self._project_directory(str(args.get("fixtureRoot") or "")),
        )

    def _lab_campaign(self, args: dict[str, Any]) -> dict[str, Any]:
        endpoint = RemoteEndpoint.load(self._project_path(str(args.get("endpointPath") or "")), trust_home=self.home)
        output_dir = self._output_path(str(args.get("outputDir") or ""), "windows-certification-runs")
        output_dir.mkdir(parents=True, exist_ok=True)
        campaign_output = self._output_path(str(args.get("campaignOutputPath") or ""), "windows-certification-campaign.dsse.json")
        return run_certification_campaign(
            endpoint=endpoint,
            image_manifest=self._project_path(str(args.get("imageManifestPath") or "")),
            fixture_root=self._project_directory(str(args.get("fixtureRoot") or "")),
            output_dir=output_dir,
            campaign_output=campaign_output,
            private_key=self._project_path(str(args.get("privateKeyPath") or "")),
            public_key=self._project_path(str(args.get("publicKeyPath") or "")),
            campaign_id=str(args.get("campaignId") or ""),
            iterations=int(args.get("iterations") or 3),
            timeout=int(args.get("timeout") or 1800),
        )

    def _lab_verify_campaign(self, args: dict[str, Any]) -> dict[str, Any]:
        return verify_campaign_attestation(
            self._project_path(str(args.get("campaignPath") or "")),
            public_key=self._project_path(str(args.get("publicKeyPath") or "")),
            image_manifest=self._project_path(str(args.get("imageManifestPath") or "")),
            fixture_root=self._project_directory(str(args.get("fixtureRoot") or "")),
            attestation_dir=self._project_directory(str(args.get("attestationDir") or "")),
            minimum_runs=int(args.get("minimumRuns") or 2),
        )

    def _lab_profiles(self, args: dict[str, Any]) -> dict[str, Any]:
        return lab_profiles()

    def _lab_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        manifest = self._project_path(str(args.get("manifestPath") or ""))
        output = self._output_path(args.get("outputPath"), "windows-hyperv-plan.json")
        return build_provision_plan(manifest, output=output)

    def _lab_build_provisioning_kit(self, args: dict[str, Any]) -> dict[str, Any]:
        output = self._output_path(str(args.get("outputPath") or ""), "windows-lab-provisioning-kit.zip")
        plan = self._project_path(str(args["planPath"])) if args.get("planPath") else None
        private_key = self._project_path(str(args["privateKeyPath"])) if args.get("privateKeyPath") else None
        public_key = self._project_path(str(args["publicKeyPath"])) if args.get("publicKeyPath") else None
        return build_provisioning_kit(
            self.root, output, version=__version__, plan_path=plan,
            signing_private_key=private_key, signing_public_key=public_key,
        )

    def _lab_verify_provisioning_kit(self, args: dict[str, Any]) -> dict[str, Any]:
        public_key = self._project_path(str(args["publicKeyPath"])) if args.get("publicKeyPath") else None
        return verify_provisioning_kit(
            self._project_path(str(args.get("packagePath") or "")), signing_public_key=public_key,
        )

    def _lab_provision(self, args: dict[str, Any]) -> dict[str, Any]:
        endpoint = RemoteEndpoint.load(self._project_path(str(args.get("endpointPath") or "")), trust_home=self.home)
        result = provision_remote_hyperv_lab(
            endpoint,
            plan_path=self._project_path(str(args.get("planPath") or "")),
            source_root=self.root,
            timeout=int(args.get("timeout") or 7200),
        )
        report = self._output_path(args.get("reportPath"), "windows-lab-provision-report.json")
        atomic_write_json(report, result)
        return {"status": result.get("status"), "reportPath": report.relative_to(self.root).as_posix(), "images": result.get("provision", {}).get("images")}

    def _lab_authoritative_matrix(self, args: dict[str, Any]) -> dict[str, Any]:
        output_dir = self._output_path(str(args.get("outputDir") or ""), "windows-authoritative-runs")
        output_dir.mkdir(parents=True, exist_ok=True)
        matrix_output = self._output_path(str(args.get("matrixOutputPath") or ""), "windows-authoritative-matrix.dsse.json")
        return run_authoritative_matrix(
            self._project_path(str(args.get("specPath") or "")),
            output_dir=output_dir,
            matrix_output=matrix_output,
            private_key=self._project_path(str(args.get("privateKeyPath") or "")),
            public_key=self._project_path(str(args.get("publicKeyPath") or "")),
            trust_home=self.home,
            release_binding_path=self._project_path(str(args.get("releaseBindingPath") or "")),
            timeout=int(args.get("timeout") or 1800),
        )

    def _lab_verify_authoritative_matrix(self, args: dict[str, Any]) -> dict[str, Any]:
        return verify_authoritative_matrix_attestation(
            self._project_path(str(args.get("attestationPath") or "")),
            public_key=self._project_path(str(args.get("publicKeyPath") or "")),
        )

    def _full_init(self, args: dict[str, Any]) -> dict[str, Any]:
        output = self._output_path(args.get("outputPath"), "psmatrix.full.json")
        return write_full_matrix_template(output)

    def _full_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        result = plan_full_matrix(
            home=self.home,
            spec_path=self._project_path(str(args.get("specPath") or "")),
        )
        if args.get("outputPath"):
            atomic_write_json(self._output_path(str(args["outputPath"]), "full-matrix-plan.json"), result)
        return result

    def _full_test(self, args: dict[str, Any]) -> dict[str, Any]:
        entrypoint = self._project_path(str(args.get("entrypoint") or ""))
        include = [self._project_path(str(item)) for item in (args.get("include") or [])]
        remote_options: dict[str, Any] = {}
        if args.get("remoteOptionsPath"):
            value = read_json(self._project_path(str(args["remoteOptionsPath"])))
            if not isinstance(value, dict):
                raise RepairError("Full matrix remote options root must be an object")
            remote_options = value
        report = execute_full_matrix(
            home=self.home,
            root=self.root,
            entrypoint=entrypoint,
            spec_path=self._project_path(str(args.get("specPath") or "")),
            include=include,
            local_args=[str(item) for item in (args.get("localArgs") or [])],
            remote_options=remote_options,
            timeout=int(args.get("timeout") or 1200),
            jobs=int(args.get("jobs") or 0),
            differential_mode=str(args["differential"]) if args.get("differential") else None,
        )
        output = self._output_path(args.get("reportPath"), "full-matrix-report.json")
        atomic_write_json(output, report.to_dict())
        return {
            "status": report.status,
            "reportPath": output.relative_to(self.root).as_posix(),
            "coverage": report.matrix.get("coverage"),
            "unallowedDifferences": report.matrix.get("unallowed_differences"),
        }

    def _complete(self, value: Any, *, error: bool = False) -> dict[str, Any]:
        text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        return {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "structuredContent": value,
            "isError": error,
        }

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = message.get("method")
        if method == "notifications/initialized":
            if self.negotiated:
                self.initialized = True
            return None
        if method == "initialize":
            params = message.get("params") or {}
            requested = str(params.get("protocolVersion") or "2025-11-25")
            self.protocol = requested if requested in SUPPORTED_PROTOCOLS else "2025-11-25"
            self.negotiated = True
            self.initialized = False
            return self._result(request_id, {
                "protocolVersion": self.protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "psmatrix", "title": "PSMatrix PowerShell Validation", "version": __version__,
                    "description": "Hash-bound PowerShell testing, transactional repair, and delivery gates.",
                },
                "instructions": "Test every generated PowerShell file. Apply changes only through transactional repair and require a valid delivery gate before claiming completion.",
            })
        if method == "server/discover":
            return self._result(request_id, {
                "resultType": "complete",
                "supportedVersions": list(SUPPORTED_PROTOCOLS),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "psmatrix", "version": __version__},
            })
        if method == "ping":
            return self._result(request_id, {"resultType": "complete"})
        if method == "tools/list":
            if not self.initialized:
                return self._error(request_id, -32002, "MCP session is not initialized")
            return self._result(request_id, {
                "resultType": "complete",
                "tools": tool_definitions(),
                "ttlMs": 300000,
                "cacheScope": "private",
            })
        if method == "tools/call":
            if not self.initialized:
                return self._error(request_id, -32002, "MCP session is not initialized")
            params = message.get("params") or {}
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return self._error(request_id, -32602, "Tool arguments must be an object")
            handler = self._tools.get(name)
            definition = next((tool for tool in tool_definitions() if tool["name"] == name), None)
            if handler is None or definition is None:
                return self._error(request_id, -32602, f"Unknown tool: {name}")
            try:
                _validate_schema(arguments, definition["inputSchema"])
                return self._result(request_id, self._complete(handler(arguments)))
            except Exception as exc:
                return self._result(request_id, self._complete({
                    "error": f"{type(exc).__name__}: {exc}",
                    "tool": name,
                }, error=True))
        return self._error(request_id, -32601, f"Method not found: {method}") if request_id is not None else None

    @staticmethod
    def _result(request_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


def serve_stdio(root: Path, home: Path) -> int:
    server = MCPServer(root, home)
    for raw in sys.stdin.buffer:
        if len(raw) > _MAX_MESSAGE_BYTES:
            response = MCPServer._error(None, -32600, "MCP message exceeds size limit")
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
            continue
        try:
            message = json.loads(raw.decode("utf-8"))
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("Expected a JSON-RPC 2.0 object")
            response = server.handle(message)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            response = MCPServer._error(None, -32700, f"Parse error: {exc}")
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0
