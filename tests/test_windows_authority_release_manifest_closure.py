import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Test-PSMatrixWindowsAuthorityReleaseManifestClosure.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "media-canonicalization-contract.json"


class WindowsAuthorityReleaseManifestClosureTests(unittest.TestCase):
    def test_contract_and_script_freeze_fail_closed_boundary(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertTrue(
            contract["rules"][
                "signed_release_manifest_must_declare_each_release_bound_role"
            ]
        )
        self.assertEqual(
            contract["required_release_artifacts"],
            {
                "source-archive": "-source.zip",
                "windows-workers-package": "-windows-workers.zip",
                "windows-certification-kit": "-windows-certification-kit.zip",
                "windows-provisioning-kit": "-windows-provisioning-kit.zip",
            },
        )

        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "required_release_artifacts",
            "INCOMPLETE",
            "missing_release_roles",
            "ambiguous_release_roles",
            "ready_for_release_artifact_recovery",
            "downloads_files = $false",
            "extracts_archives = $false",
            "writes_release_artifacts = $false",
            "opens_secret_bundles = $false",
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
    def test_public_rc2_shape_is_incomplete_for_windows_authority(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)

        with tempfile.TemporaryDirectory(prefix="psmatrix-release-closure-") as temporary:
            root = Path(temporary)
            ga = root / "ga"
            ga.mkdir()

            manifest = root / "psmatrix-2.0.0rc2-release.json"
            manifest.write_text(
                json.dumps(
                    {
                        "manifest": {
                            "schema": 1,
                            "kind": "psmatrix.release-manifest",
                            "version": "2.0.0rc2",
                            "artifacts": [
                                {
                                    "name": "psmatrix-2.0.0rc2-source.zip",
                                    "sha256": hashlib.sha256(b"source").hexdigest(),
                                    "size": 6,
                                }
                            ],
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

            canonical = ga / "windows-authority-media-inventory.canonical.json"
            canonical.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "psmatrix.windows-authority-media-inventory",
                        "pack": "03-authoritative-windows",
                        "authoritative": False,
                        "ga_eligible": False,
                        "canonicalization": {
                            "release_authority_status": "READY",
                            "release_version": "2.0.0rc2",
                            "selected_manifest_path": str(manifest),
                            "selected_manifest_sha256": manifest_sha,
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            output = ga / "windows-authority-release-manifest-closure.json"
            result = subprocess.run(
                [
                    str(pwsh),
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(SCRIPT),
                    "-SourceRoot",
                    str(ROOT),
                    "-GaRoot",
                    str(ga),
                    "-CanonicalInventoryPath",
                    str(canonical),
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
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(report["errors"], [])
            self.assertEqual(
                set(report["missing_release_roles"]),
                {
                    "windows-workers-package",
                    "windows-certification-kit",
                    "windows-provisioning-kit",
                },
            )
            self.assertEqual(report["ambiguous_release_roles"], [])
            self.assertFalse(report["ready_for_release_artifact_recovery"])
            self.assertFalse(report["authoritative"])
            self.assertFalse(report["ga_eligible"])


if __name__ == "__main__":
    unittest.main()
