# Pack 03 — Authoritative Windows Lab

## Objective

Produce exact Windows PowerShell 4.0, 5.0 and 5.1 evidence on trusted Hyper-V VMs.

## Required campaign

Each runtime must complete repeated clean-snapshot campaigns covering Registry, Services, COM, WMI, Event Log, Scheduled Tasks, NTFS ACL, certificate store and process checks. Reset-before and reset-after evidence is mandatory.

The immutable runner and campaign requirements are stored in `runner-contract.json`. Every authoritative worker must use the exact runtime-specific self-hosted labels from that contract. GitHub-hosted runners are never treated as the protected Windows-lab authority.

## Hosted Windows 5.1 preflight

Workflow: `production-ga-windows-authority-preflight`

The workflow runs the PowerShell 4-compatible `windows-authority-probe.ps1` with real Windows PowerShell 5.1 on GitHub-hosted Windows Server. It verifies:

- exact Windows PowerShell 5.1 Desktop identity;
- Registry write/read/cleanup;
- Windows Service query;
- COM activation;
- WMI query;
- Event Log query;
- Scheduled Task query;
- NTFS ACL roundtrip;
- certificate-store query;
- process and Windows environment identity.

A green hosted preflight is recorded as `PASS_PARTIAL`, never as authoritative completion. GitHub-hosted runners cannot provide the required clean Hyper-V snapshot reset statements, protected lab identity, Windows PowerShell 4.0, or Windows PowerShell 5.0.

## Release binding

The final matrix proof must bind the exact final commit, signed release manifest, source ZIP, worker package, certification kit and provisioning kit.

## State

`HOSTED_WINDOWS_5_1_PREFLIGHT_PENDING` — the real Windows PowerShell 5.1 preflight workflow is ready. Authoritative 4.0/5.0/5.1 Hyper-V workers, repeated reset-bound campaigns and the protected Windows-lab signature remain required.
