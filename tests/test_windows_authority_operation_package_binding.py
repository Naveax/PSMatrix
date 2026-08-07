import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "operation-package-binding-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class WindowsAuthorityOperationPackageBindingTests(unittest.TestCase):
    def test_contract_freezes_stale_binding_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-operation-package-binding-contract",
        )
        self.assertTrue(
            value["rules"][
                "operation_package_release_manifest_sha256_must_match_canonical_manifest"
            ]
        )
        self.assertTrue(value["rules"]["stale_binding_blocks_artifact_recovery"])
        self.assertTrue(value["rules"]["zip_entry_inventory_is_read_only"])
        self.assertFalse(value["safety"]["downloads_files"])
        self.assertFalse(value["safety"]["extracts_archives"])
        self.assertFalse(value["safety"]["writes_release_artifacts"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_script_is_read_only_and_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "release_manifest_matches_canonical",
            "STALE_BINDING",
            "ready_for_release_artifact_recovery",
            "System.IO.Compression.ZipFile",
            "Get-ZipEntrySha256",
            "embedded_release_artifacts_match_binding",
            "$matchingEntries = @(",
            "downloads_files = $false",
            "extracts_archives = $false",
            "writes_release_artifacts = $false",
            "authoritative = $false",
            "ga_eligible = $false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "Expand-Archive",
            "ExtractToDirectory",
            "Copy-Item",
            "Move-Item -LiteralPath $operationZipPath",
            "$matches = @(",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "authoritative = $true",
            "ga_eligible = $true",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for runtime validation")
    def test_stale_package_is_detected_without_extraction(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)

        with tempfile.TemporaryDirectory(prefix="psmatrix-operation-binding-") as temporary:
            root = Path(temporary)
            source = root / "source"
            ga = root / "ga"
            metadata_dir = root / "operation"
            contract_dir = source / "ga-packs" / "03-authoritative-windows"
            contract_dir.mkdir(parents=True)
            ga.mkdir()
            metadata_dir.mkdir()
            shutil.copy2(CONTRACT, contract_dir / CONTRACT.name)

            release_manifest = root / "psmatrix-2.0.0rc2-release.json"
            release_manifest.write_text(
                json.dumps(
                    {
                        "manifest": {
                            "schema": 1,
                            "kind": "psmatrix.release-manifest",
                            "version": "2.0.0rc2",
                            "artifacts": [],
                        }
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            current_manifest_sha = hashlib.sha256(release_manifest.read_bytes()).hexdigest()

            canonical = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-media-inventory",
                "pack": "03-authoritative-windows",
                "authoritative": False,
                "ga_eligible": False,
                "canonicalization": {
                    "release_authority_status": "READY",
                    "release_version": "2.0.0rc2",
                    "selected_manifest_path": str(release_manifest),
                    "selected_manifest_sha256": current_manifest_sha,
                },
            }
            canonical_path = ga / "windows-authority-media-inventory.canonical.json"
            canonical_path.write_text(json.dumps(canonical), encoding="utf-8")

            artifact_bytes = {
                "psmatrix-2.0.0rc2-source.zip": b"source\n",
                "psmatrix-2.0.0rc2-windows-workers.zip": b"workers\n",
                "psmatrix-2.0.0rc2-windows-certification-kit.zip": b"certification\n",
                "psmatrix-2.0.0rc2-windows-provisioning-kit.zip": b"provisioning\n",
            }
            operation_zip = metadata_dir / "psmatrix-2.0.0rc2-windows-authoritative-operation.zip"
            with zipfile.ZipFile(operation_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in artifact_bytes.items():
                    archive.writestr(name, data)

            operation_zip_bytes = operation_zip.read_bytes()
            metadata = {
                "schema": 1,
                "kind": "psmatrix.windows-authoritative-operation-package",
                "artifact": {
                    "name": operation_zip.name,
                    "sha256": sha256_bytes(operation_zip_bytes),
                    "size": len(operation_zip_bytes),
                },
                "release_commit": "6" * 40,
                "release_binding": {
                    "valid": True,
                    "release_manifest_sha256": "7" * 64,
                    "source_sha256": sha256_bytes(artifact_bytes["psmatrix-2.0.0rc2-source.zip"]),
                    "windows_workers_sha256": sha256_bytes(
                        artifact_bytes["psmatrix-2.0.0rc2-windows-workers.zip"]
                    ),
                    "windows_certification_kit_sha256": sha256_bytes(
                        artifact_bytes[
                            "psmatrix-2.0.0rc2-windows-certification-kit.zip"
                        ]
                    ),
                    "windows_provisioning_kit_sha256": sha256_bytes(
                        artifact_bytes[
                            "psmatrix-2.0.0rc2-windows-provisioning-kit.zip"
                        ]
                    ),
                },
            }
            metadata_path = metadata_dir / "operation-package.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            output = ga / "windows-authority-operation-package-binding.json"
            result = subprocess.run(
                [
                    str(pwsh),
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(SCRIPT),
                    "-SourceRoot",
                    str(source),
                    "-GaRoot",
                    str(ga),
                    "-CanonicalInventoryPath",
                    str(canonical_path),
                    "-OperationPackageMetadataPath",
                    str(metadata_path),
                    "-OutputPath",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            report_debug = json.dumps(report, indent=2, sort_keys=True)
            self.assertEqual(report["errors"], [], msg=report_debug)
            self.assertEqual(report["status"], "STALE_BINDING", msg=report_debug)
            self.assertFalse(report["ready_for_release_artifact_recovery"])
            self.assertTrue(report["operation_package"]["release_binding_valid"])
            self.assertFalse(
                report["operation_package"]["release_manifest_matches_canonical"]
            )
            self.assertTrue(report["operation_package"]["zip_sha256_matches_metadata"])
            self.assertTrue(report["operation_package"]["zip_size_matches_metadata"])
            self.assertTrue(
                report["operation_package"][
                    "embedded_release_artifacts_match_binding"
                ]
            )
            self.assertEqual(len(report["operation_package"]["relevant_zip_entries"]), 4)

    def test_source_preflight_tracks_operation_package_binding(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "scripts/ga/Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1",
            "tests/test_windows_authority_operation_package_binding.py",
            "tests.test_windows_authority_operation_package_binding",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
