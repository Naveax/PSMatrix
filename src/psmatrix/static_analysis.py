from __future__ import annotations

import re
from pathlib import Path
from typing import Any

WINDOWS_CAPABILITIES: list[tuple[str, re.Pattern[str]]] = [
    ("registry", re.compile(r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC):?\\|Registry::")),
    ("windows-services", re.compile(r"(?i)\b(?:Start|Stop|Restart|Set|New|Remove)-Service\b")),
    ("scheduled-tasks", re.compile(r"(?i)\b(?:Get|New|Set|Start|Stop|Unregister)-ScheduledTask\b")),
    ("com", re.compile(r"(?i)-ComObject\b|System\.__ComObject")),
    ("wmi", re.compile(r"(?i)\bGet-WmiObject\b|root\\cimv2|\bWin32_[A-Za-z0-9_]+\b")),
    ("active-directory", re.compile(r"(?i)\b(?:Get|Set|New|Remove)-AD(?:User|Group|Computer|Object)\b|Import-Module\s+ActiveDirectory")),
    ("iis", re.compile(r"(?i)\bWebAdministration\b|IIS:\\")),
    ("dism", re.compile(r"(?i)\b(?:dism|sfc|bcdedit|pnputil)(?:\.exe)?\b")),
    ("windows-firewall", re.compile(r"(?i)\bNetSecurity\b|\b(?:Get|New|Set|Remove)-NetFirewallRule\b")),
    ("windows-defender", re.compile(r"(?i)\b(?:Get|Set|Add|Remove)-MpPreference\b|Start-MpScan")),
    ("bitlocker", re.compile(r"(?i)\bBitLocker\b|\b(?:Get|Enable|Disable|Lock|Unlock)-BitLocker\b")),
]

RISK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dynamic-execution", re.compile(r"(?i)\bInvoke-Expression\b|\biex\b")),
    ("encoded-command", re.compile(r"(?i)-(?:EncodedCommand|enc)\b")),
    ("recursive-delete", re.compile(r"(?i)\bRemove-Item\b[^\n]*-(?:Recurse|r)\b")),
    ("download-execute", re.compile(r"(?is)(Invoke-WebRequest|curl|wget).{0,500}(Invoke-Expression|Start-Process|&\s*\$)")),
]

_WINDOWS_COMMAND_GROUPS: dict[str, set[str]] = {
    "windows-services": {
        "get-service", "start-service", "stop-service", "restart-service",
        "set-service", "new-service", "remove-service",
    },
    "scheduled-tasks": {
        "get-scheduledtask", "new-scheduledtask", "set-scheduledtask",
        "start-scheduledtask", "stop-scheduledtask", "unregister-scheduledtask",
    },
    "wmi": {"get-wmiobject", "invoke-wmimethod", "set-wmiinstance", "remove-wmiobject"},
    "active-directory": {
        "get-aduser", "set-aduser", "new-aduser", "remove-aduser",
        "get-adgroup", "set-adgroup", "new-adgroup", "remove-adgroup",
        "get-adcomputer", "set-adcomputer", "new-adcomputer", "remove-adcomputer",
        "get-adobject", "set-adobject", "new-adobject", "remove-adobject",
    },
    "windows-firewall": {
        "get-netfirewallrule", "new-netfirewallrule", "set-netfirewallrule", "remove-netfirewallrule",
    },
    "windows-defender": {
        "get-mppreference", "set-mppreference", "add-mppreference", "remove-mppreference", "start-mpscan",
    },
    "bitlocker": {
        "get-bitlockervolume", "enable-bitlocker", "disable-bitlocker", "lock-bitlocker", "unlock-bitlocker",
    },
}

_NETWORK_COMMANDS = {
    "invoke-webrequest", "invoke-restmethod", "test-netconnection", "resolve-dnsname",
    "curl", "curl.exe", "wget", "wget.exe", "ssh", "scp", "sftp", "ftp",
}
_PROCESS_COMMANDS = {
    "start-process", "start-job", "start-threadjob", "invoke-command",
    "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe", "bash", "sh",
}
_WRITE_COMMANDS = {
    "set-content", "add-content", "out-file", "new-item", "remove-item", "move-item",
    "copy-item", "rename-item", "set-item", "clear-content", "export-csv", "export-clixml",
    "set-acl", "set-itemproperty", "new-itemproperty", "remove-itemproperty",
}
_READ_COMMANDS = {
    "get-content", "get-childitem", "get-item", "test-path", "import-csv", "import-clixml",
}
_DYNAMIC_COMMANDS = {"invoke-expression", "iex"}
_DOWNLOAD_COMMANDS = {"invoke-webrequest", "invoke-restmethod", "curl", "curl.exe", "wget", "wget.exe"}
_EXECUTE_COMMANDS = _DYNAMIC_COMMANDS | _PROCESS_COMMANDS


def _finding(
    code: str,
    severity: str,
    category: str,
    message: str,
    item: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item = item or {}
    return {
        "code": code,
        "severity": severity,
        "category": category,
        "message": message,
        "line": item.get("line"),
        "column": item.get("column"),
        "evidence": item.get("text") or item.get("value"),
    }


def _command_name(item: dict[str, Any]) -> str:
    return str(item.get("name") or "").strip().lower()


def _extract_imported_module(command: dict[str, Any]) -> str | None:
    elements = [str(value).strip("'\"") for value in command.get("elements", [])]
    if not elements or _command_name(command) != "import-module":
        return None
    skip_next = False
    for value in elements[1:]:
        if skip_next:
            skip_next = False
            continue
        if value.startswith("-"):
            if value.lower() in {"-name", "-fullyqualifiedname", "-requiredversion", "-minimumversion", "-maximumversion"}:
                skip_next = value.lower() != "-name"
            continue
        if not value.startswith("$"):
            return value
    return None


def _parse_requires_modules(text: str) -> list[str]:
    match = re.search(r"(?i)-Modules?\s+(.+?)(?=\s+-[A-Za-z]|$)", text)
    if not match:
        return []
    value = match.group(1).strip()
    # Covers the common `#requires -Modules A,B` form. Hashtable module
    # specifications remain visible in the raw requirement record.
    return [item.strip(" '\"{}") for item in value.split(",") if item.strip(" '\"{}")]


def _classify_ast(ast: dict[str, Any]) -> dict[str, Any]:
    commands = [item for item in ast.get("commands", []) if isinstance(item, dict)]
    command_names = [_command_name(item) for item in commands]
    command_set = {name for name in command_names if name}
    type_names = sorted({str(value) for value in ast.get("type_names", []) if value})
    provider_paths = [item for item in ast.get("provider_paths", []) if isinstance(item, dict)]

    findings: list[dict[str, Any]] = []
    windows: set[str] = set()
    risks: set[str] = set()
    modules: set[str] = set()
    native_commands: set[str] = set()

    for command in commands:
        name = _command_name(command)
        parameters = {str(value).lower() for value in command.get("parameters", [])}
        invocation = str(command.get("invocation_operator") or "").lower()
        if not name and invocation not in {"unknown", "none", ""}:
            risks.add("dynamic-execution")
            findings.append(_finding(
                "PSM1001", "high", "dynamic-execution",
                "Command target is computed dynamically and cannot be resolved statically", command,
            ))
        if name in _DYNAMIC_COMMANDS:
            risks.add("dynamic-execution")
            findings.append(_finding(
                "PSM1002", "high", "dynamic-execution",
                f"Dynamic PowerShell evaluation through {command.get('name')}", command,
            ))
        if name == "remove-item" and ({"recurse", "r"} & parameters):
            risks.add("recursive-delete")
            findings.append(_finding(
                "PSM1003", "high", "destructive-filesystem",
                "Recursive filesystem deletion", command,
            ))
        if name in _PROCESS_COMMANDS:
            risks.add("process-spawn")
            findings.append(_finding(
                "PSM1004", "medium", "process-spawn",
                f"Starts or delegates execution through {command.get('name')}", command,
            ))
        if name in _NETWORK_COMMANDS:
            findings.append(_finding(
                "PSM1101", "info", "network",
                f"Network-capable command {command.get('name')}", command,
            ))
        if name == "new-object" and "comobject" in parameters:
            windows.add("com")
        for capability, names in _WINDOWS_COMMAND_GROUPS.items():
            if name in names:
                windows.add(capability)
        if name in {"dism", "dism.exe", "sfc", "sfc.exe", "bcdedit", "bcdedit.exe", "pnputil", "pnputil.exe"}:
            windows.add("dism")
        module = _extract_imported_module(command)
        if module:
            modules.add(module)
            module_lower = module.lower()
            if module_lower == "activedirectory":
                windows.add("active-directory")
            elif module_lower == "webadministration":
                windows.add("iis")
            elif module_lower == "netsecurity":
                windows.add("windows-firewall")
        # Native utilities generally lack PowerShell's Verb-Noun shape or use
        # an explicit executable suffix. Custom functions remain unclassified.
        display_name = str(command.get("name") or "")
        if display_name and (display_name.lower().endswith(".exe") or "-" not in display_name):
            if name not in {"foreach", "where", "sort", "select", "%", "?"}:
                native_commands.add(display_name)

    if command_set & _DOWNLOAD_COMMANDS and command_set & _EXECUTE_COMMANDS:
        risks.add("download-execute")
        findings.append(_finding(
            "PSM1005", "critical", "download-execute",
            "Script contains both download and execution primitives",
        ))

    for path_item in provider_paths:
        value = str(path_item.get("value") or "")
        lower = value.lower()
        if re.match(r"^(hklm|hkcu|hkcr|hku|hkcc):", lower) or lower.startswith("registry::"):
            windows.add("registry")
        if lower.startswith("iis:"):
            windows.add("iis")
        if lower.startswith("\\\\"):
            findings.append(_finding(
                "PSM1102", "info", "network-filesystem", "UNC/network path reference", path_item
            ))

    for type_name in type_names:
        lower = type_name.lower()
        if "system.__comobject" in lower:
            windows.add("com")
        if lower.startswith("system.reflection") or ".reflection." in lower:
            risks.add("reflection")
            findings.append(_finding(
                "PSM1006", "medium", "reflection", f"Reflection-capable .NET type: {type_name}"
            ))
        if lower.startswith("microsoft.win32.registry"):
            windows.add("registry")
        if lower.startswith("system.directoryservices"):
            windows.add("active-directory")

    for using in ast.get("using_statements", []):
        if not isinstance(using, dict):
            continue
        if str(using.get("kind") or "").lower() == "module":
            name = str(using.get("name") or "").strip()
            if name:
                modules.add(name)

    requirements = []
    requires_admin = False
    for requirement in ast.get("requires", []):
        if not isinstance(requirement, dict):
            continue
        text = str(requirement.get("text") or "")
        requirements.append(text)
        modules.update(_parse_requires_modules(text))
        if re.search(r"(?i)-RunAsAdministrator\b", text):
            requires_admin = True

    capabilities = {
        "filesystem_read": bool(command_set & _READ_COMMANDS),
        "filesystem_write": bool(command_set & _WRITE_COMMANDS),
        "network": bool(command_set & _NETWORK_COMMANDS) or any(
            str(item.get("value") or "").startswith("\\\\") for item in provider_paths
        ),
        "process_spawn": bool(command_set & _PROCESS_COMMANDS),
        "dynamic_execution": bool(risks & {"dynamic-execution", "download-execute"}),
        "requires_admin": requires_admin,
    }

    return {
        "windows_requirements": sorted(windows),
        "risks": sorted(risks),
        "findings": findings,
        "dependencies": {
            "modules": sorted(modules, key=str.lower),
            "native_commands": sorted(native_commands, key=str.lower),
            "dotnet_types": type_names,
            "requirements": requirements,
        },
        "capabilities": capabilities,
        "ast": ast,
    }


def _lexical_analysis(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    windows = [name for name, pattern in WINDOWS_CAPABILITIES if pattern.search(text)]
    risks = [name for name, pattern in RISK_PATTERNS if pattern.search(text)]
    findings = [
        _finding("PSM0900", "warning", risk, f"Lexical fallback detected {risk}")
        for risk in sorted(set(risks))
    ]
    return {
        "windows_requirements": sorted(set(windows)),
        "risks": sorted(set(risks)),
        "findings": findings,
        "dependencies": {
            "modules": [],
            "native_commands": [],
            "dotnet_types": [],
            "requirements": [],
        },
        "capabilities": {
            "filesystem_read": False,
            "filesystem_write": False,
            "network": False,
            "process_spawn": False,
            "dynamic_execution": "dynamic-execution" in risks,
            "requires_admin": False,
        },
        "ast": None,
        "analysis_mode": "lexical-fallback",
    }


def analyze_source(path: Path, ast_analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    lexical = _lexical_analysis(path)
    if not ast_analysis:
        return lexical
    ast_result = _classify_ast(ast_analysis)
    ast_result["windows_requirements"] = sorted(
        set(ast_result["windows_requirements"]) | set(lexical["windows_requirements"])
    )
    ast_result["risks"] = sorted(set(ast_result["risks"]) | set(lexical["risks"]))
    existing = {(item["code"], item.get("line"), item.get("evidence")) for item in ast_result["findings"]}
    for item in lexical["findings"]:
        key = (item["code"], item.get("line"), item.get("evidence"))
        if key not in existing:
            ast_result["findings"].append(item)
    ast_result["analysis_mode"] = "target-runtime-ast"
    return ast_result
