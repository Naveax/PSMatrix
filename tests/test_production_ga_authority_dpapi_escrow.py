from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Protect-ProductionGAAuthorityEscrow.ps1"
ROLES = (
    "release",
    "windows-lab",
    "ci",
    "deployment",
    "operations",
    "recovery",
    "security-review",
    "vulnerability-scanner",
    "root",
)
ENVIRONMENTS = {
    "release": "production-ga-release-signing",
    "windows-lab": "production-ga-windows-lab",
    "ci": "production-ga-ci-signing",
    "deployment": "production-ga-deployment-signing",
    "operations": "production-ga-operations-signing",
    "recovery": "production-ga-recovery-signing",
    "security-review": "production-ga-security-review-signing",
    "vulnerability-scanner": "production-ga-vulnerability-scanner-signing",
    "root": "production-ga-root-signing",
}
PRIVATE_SECRETS = {
    "release": "PSMATRIX_RELEASE_PRIVATE_KEY",
    "windows-lab": "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
    "ci": "PSMATRIX_GA_CI_PRIVATE_KEY",
    "deployment": "PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY",
    "operations": "PSMATRIX_GA_OPERATIONS_PRIVATE_KEY",
    "recovery": "PSMATRIX_GA_RECOVERY_PRIVATE_KEY",
    "security-review": "PSMATRIX_GA_SECURITY_REVIEW_PRIVATE_KEY",
    "vulnerability-scanner": "PSMATRIX_GA_VULNERABILITY_SCANNER_PRIVATE_KEY",
    "root": "PSMATRIX_GA_ROOT_PRIVATE_KEY",
}
PUBLIC_SECRETS = {
    "release": None,
    "windows-lab": "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY",
    "ci": "PSMATRIX_GA_CI_PUBLIC_KEY",
    "deployment": "PSMATRIX_GA_DEPLOYMENT_PUBLIC_KEY",
    "operations": "PSMATRIX_GA_OPERATIONS_PUBLIC_KEY",
    "recovery": "PSMATRIX_GA_RECOVERY_PUBLIC_KEY",
    "security-review": "PSMATRIX_GA_SECURITY_REVIEW_PUBLIC_KEY",
    "vulnerability-scanner": "PSMATRIX_GA_VULNERABILITY_SCANNER_PUBLIC_KEY",
    "root": "PSMATRIX_GA_ROOT_PUBLIC_KEY",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_fake_authorities(root: Path) -> tuple[dict[str, bytes], dict[str, bytes]]:
    root.mkdir(parents=True)
    private_values: dict[str, bytes] = {}
    public_values: dict[str, bytes] = {}
    rows = []
    for index, role in enumerate(ROLES, start=1):
        private = f"PRIVATE-TEST-MATERIAL-{role}-{index}\n".encode()
        public = f"PUBLIC-TEST-MATERIAL-{role}-{index}\n".encode()
        private_name = f"{role}.private.pem"
        public_name = f"{role}.public.pem"
        (root / private_name).write_bytes(private)
        (root / public_name).write_bytes(public)
        private_values[role] = private
        public_values[role] = public
        rows.append(
            {
                "role": role,
                "environment": ENVIRONMENTS[role],
                "algorithm": "Ed25519",
                "private_secret": PRIVATE_SECRETS[role],
                "public_secret": PUBLIC_SECRETS[role],
                "private_file": private_name,
                "public_file": public_name,
                "public_key_id": f"test-key-{index:02d}",
                "public_key_sha256": sha256(public),
            }
        )
    manifest = {
        "schema": 1,
        "kind": "psmatrix.production-ga-authority-provisioning-manifest",
        "version": "2.0.0",
        "authority_count": 9,
        "private_secret_count": 9,
        "public_secret_count": 8,
        "readiness_secret_check_count": 17,
        "authorities": rows,
        "safety": {
            "private_key_values_serialized": False,
            "private_key_hashes_serialized": False,
            "private_key_lengths_serialized": False,
            "private_keys_written_outside_repository": True,
        },
    }
    (root / "production-ga-authorities.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return private_values, public_values


class ProductionGAAuthorityDpapiEscrowTests(unittest.TestCase):
    def test_source_freezes_final_authority_and_secret_observation_boundaries(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("ProtectedData", text)
        self.assertIn("DataProtectionScope]::CurrentUser", text)
        self.assertIn("psmatrix.production-ga-dpapi-authority-escrow", text)
        self.assertIn("authority_count = 9", text)
        self.assertIn("readiness_secret_check_count = 17", text)
        self.assertIn("private_key_values_serialized = $false", text)
        self.assertIn("private_key_hashes_serialized = $false", text)
        self.assertIn("private_key_lengths_serialized = $false", text)
        self.assertIn("dpapi_round_trip_verified = $true", text)
        self.assertIn("RemovePlaintextPrivateKeys", text)
        self.assertNotIn("2.0.0rc4", text)
        self.assertNotIn("PSMATRIX_WPS40_ADMIN_PASSWORD", text)

    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "Windows PowerShell 7 required for DPAPI round-trip")
    def test_real_dpapi_protect_remove_restore_and_tamper_rejection(self) -> None:
        pwsh = shutil.which("pwsh")
        assert pwsh is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority = root / "authorities"
            escrow = root / "escrow"
            restored = root / "restored"
            protect_report = root / "protect-report.json"
            restore_report = root / "restore-report.json"
            private_values, public_values = write_fake_authorities(authority)

            protect = subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-Protect",
                    "-AuthorityRoot",
                    str(authority),
                    "-EscrowRoot",
                    str(escrow),
                    "-RemovePlaintextPrivateKeys",
                    "-ReportOutput",
                    str(protect_report),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            self.assertEqual(protect.returncode, 0, protect.stdout)
            self.assertIn("production_ga_authority_dpapi_escrow=PASS action=protect", protect.stdout)
            self.assertIn("plaintext_private_keys_removed=true", protect.stdout)

            for role in ROLES:
                self.assertFalse((authority / f"{role}.private.pem").exists())
                self.assertEqual((authority / f"{role}.public.pem").read_bytes(), public_values[role])
                self.assertTrue((escrow / f"{role}.private.pem.dpapi").is_file())
                self.assertEqual((escrow / f"{role}.public.pem").read_bytes(), public_values[role])

            escrow_text = (escrow / "production-ga-authorities.dpapi-escrow.json").read_text(encoding="utf-8")
            report_text = protect_report.read_text(encoding="utf-8")
            for private in private_values.values():
                marker = private.decode().strip()
                self.assertNotIn(marker, escrow_text)
                self.assertNotIn(marker, report_text)
            self.assertNotIn("private_key_sha256", escrow_text)
            self.assertNotIn("private_key_length", escrow_text)

            restore = subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-Restore",
                    "-EscrowRoot",
                    str(escrow),
                    "-DestinationRoot",
                    str(restored),
                    "-ReportOutput",
                    str(restore_report),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            self.assertEqual(restore.returncode, 0, restore.stdout)
            self.assertIn("production_ga_authority_dpapi_escrow=PASS action=restore", restore.stdout)
            for role in ROLES:
                self.assertEqual((restored / f"{role}.private.pem").read_bytes(), private_values[role])
                self.assertEqual((restored / f"{role}.public.pem").read_bytes(), public_values[role])
            self.assertEqual(
                (restored / "production-ga-authorities.manifest.json").read_bytes(),
                (escrow / "production-ga-authorities.original-manifest.json").read_bytes(),
            )

            tampered = bytearray((escrow / "root.private.pem.dpapi").read_bytes())
            tampered[len(tampered) // 2] ^= 0x01
            (escrow / "root.private.pem.dpapi").write_bytes(tampered)
            tampered_destination = root / "tampered-restore"
            rejected = subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-Restore",
                    "-EscrowRoot",
                    str(escrow),
                    "-DestinationRoot",
                    str(tampered_destination),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "Windows PowerShell 7 required for path-boundary test")
    def test_repository_escrow_path_is_rejected_before_material_write(self) -> None:
        pwsh = shutil.which("pwsh")
        assert pwsh is not None
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "authorities"
            write_fake_authorities(authority)
            forbidden = ROOT / ".tmp-dpapi-escrow-test"
            if forbidden.exists():
                shutil.rmtree(forbidden)
            try:
                completed = subprocess.run(
                    [
                        pwsh,
                        "-NoLogo",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(SCRIPT),
                        "-Protect",
                        "-AuthorityRoot",
                        str(authority),
                        "-EscrowRoot",
                        str(forbidden),
                    ],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(forbidden.exists())
            finally:
                if forbidden.exists():
                    shutil.rmtree(forbidden)


if __name__ == "__main__":
    unittest.main()
