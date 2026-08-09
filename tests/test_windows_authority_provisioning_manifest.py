import ast
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_provisioning_manifest.py"
WRAPPER = ROOT / "scripts" / "ga" / "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "provisioning-manifest-contract.json"
)


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_windows_authority_provisioning_manifest_test", BUILDER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load provisioning-manifest builder module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityProvisioningManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_builder_is_valid_python_and_exact_runtime_set_is_frozen(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        ast.parse(source, filename=str(BUILDER))
        self.assertEqual(
            self.builder.RUNTIMES,
            (
                "windows-powershell-4.0",
                "windows-powershell-5.0",
                "windows-powershell-5.1",
            ),
        )
        self.assertEqual(
            self.builder.CANONICAL_IMAGE_IDS,
            {
                "windows-powershell-4.0": "PSMatrix-Windows-PowerShell-4.0",
                "windows-powershell-5.0": "PSMatrix-Windows-PowerShell-5.0",
                "windows-powershell-5.1": "PSMatrix-Windows-PowerShell-5.1",
            },
        )

    def test_contract_freezes_real_product_manifest_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-provisioning-manifest-contract",
        )
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertEqual(
            value["selection_kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertEqual(
            value["provisioning_profile_kind"],
            "psmatrix.windows-authority-provisioning-profile",
        )
        self.assertEqual(value["output_kind"], "psmatrix.windows-lab-media")
        self.assertEqual(
            value["required_runtime_ids"],
            [
                "windows-powershell-4.0",
                "windows-powershell-5.0",
                "windows-powershell-5.1",
            ],
        )
        self.assertEqual(
            value["runtime_media_mapping"]["windows-powershell-5.0"]["wmf_role"],
            "wmf-5.0-offline-package",
        )
        self.assertIsNone(
            value["runtime_media_mapping"]["windows-powershell-4.0"]["wmf_role"]
        )
        self.assertIsNone(
            value["runtime_media_mapping"]["windows-powershell-5.1"]["wmf_role"]
        )
        self.assertTrue(value["rules"]["reviewed_selection_hashes_reverified"])
        self.assertTrue(value["rules"]["exact_release_commit_required"])
        self.assertTrue(value["rules"]["profile_operator_review_required"])
        self.assertTrue(value["rules"]["hyper_v_generation_2_required"])
        self.assertTrue(value["rules"]["unique_worker_ports_required"])
        self.assertTrue(
            value["rules"]["expected_os_seeded_from_inspected_installation_media"]
        )
        self.assertTrue(
            value["rules"]["actual_os_identity_must_be_measured_after_provisioning"]
        )
        self.assertTrue(value["rules"]["product_loader_validation_required"])
        for key in (
            "downloads_files",
            "opens_secret_bundles",
            "reads_private_key_contents",
            "creates_virtual_machines",
            "creates_checkpoints",
            "writes_endpoint_manifests",
            "writes_image_manifests",
            "authoritative",
            "ga_eligible",
        ):
            self.assertFalse(value["safety"][key])

    def test_profile_template_has_exact_canonical_images_and_secret_env_names(self) -> None:
        value = self.builder.profile_template("a" * 40)
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"], "psmatrix.windows-authority-provisioning-profile"
        )
        self.assertEqual(value["release_commit"], "a" * 40)
        self.assertEqual(value["defaults"]["generation"], 2)
        self.assertEqual(value["defaults"]["checkpoint_name"], "psmatrix-clean")

        images = value["images"]
        self.assertEqual(len(images), 3)
        self.assertEqual(
            [row["runtime_id"] for row in images],
            list(self.builder.RUNTIMES),
        )
        self.assertEqual(
            [row["image_id"] for row in images],
            [
                "PSMatrix-Windows-PowerShell-4.0",
                "PSMatrix-Windows-PowerShell-5.0",
                "PSMatrix-Windows-PowerShell-5.1",
            ],
        )
        self.assertEqual(
            [row["admin_password_env"] for row in images],
            [
                "PSMATRIX_WPS40_ADMIN_PASSWORD",
                "PSMATRIX_WPS50_ADMIN_PASSWORD",
                "PSMATRIX_WPS51_ADMIN_PASSWORD",
            ],
        )
        self.assertEqual([row["worker_port"] for row in images], [43140, 43150, 43151])
        self.assertEqual(len({row["computer_name"] for row in images}), 3)
        self.assertTrue(all(len(row["computer_name"]) <= 15 for row in images))

    def test_builder_has_no_network_hyperv_or_private_key_operations(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        required = (
            "WindowsLabManifest.load(output)",
            '"kind": "psmatrix.windows-lab-media"',
            '"product_loader_validation": "PASS" if written else "NOT_RUN"',
            '"actual_os_identity_measured": False',
            '"creates_virtual_machines": False',
            '"creates_checkpoints": False',
            '"opens_secret_bundles": False',
            '"reads_private_key_contents": False',
            "selection_manifest_sha256",
            "profile_sha256",
            "manifest_sha256",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "requests.get(",
            "urllib.request",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "PRIVATE KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_wrapper_is_thin_and_delegates_to_python_builder(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        required = (
            "[string]$ProductSourceRoot",
            "build_windows_authority_provisioning_manifest.py",
            "--source-root",
            "--product-source-root",
            "--ga-root",
            "--release-commit",
            "--selection-manifest",
            "--profile",
            "--output",
            "--profile-template",
            "--report",
            "--write-profile-template",
            "--require-complete",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "ConvertFrom-Json",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
