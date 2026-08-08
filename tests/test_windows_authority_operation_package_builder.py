import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_windows_authority_operation_package.py"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "operation-package-builder-contract.json"
)


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_operation_package_builder_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load operation-package builder module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityOperationPackageBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_contract_freezes_rc3_builder_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-operation-package-builder-contract",
        )
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        for key in (
            "media_manifest_complete",
            "media_manifest_ready_for_hyper_v_provisioning",
            "signed_release_manifest_reverified",
            "signed_release_artifacts_must_equal_reviewed_lock",
            "canonical_manifest_sha256_must_match_disk",
            "media_manifest_inventory_sha256_must_match_disk",
        ):
            self.assertTrue(value["input_requirements"][key])
        self.assertEqual(
            value["input_requirements"]["protected_release_intake_status"],
            "RELEASE_CLOSURE_READY",
        )
        self.assertEqual(
            value["input_requirements"]["canonical_release_authority_status"],
            "READY",
        )
        for key in (
            "release_commit",
            "release_manifest_sha256",
            "source_sha256",
            "windows_workers_sha256",
            "windows_certification_kit_sha256",
            "windows_provisioning_kit_sha256",
            "windows_lab_media_sha256",
            "canonical_binding_sha256",
        ):
            self.assertTrue(value["release_binding"][key])
        self.assertEqual(
            value["package"]["kind"],
            "psmatrix.windows-authoritative-operation-package",
        )
        self.assertEqual(value["package"]["status"], "READY_FOR_WINDOWS_HOST")
        self.assertTrue(value["package"]["deterministic_zip"])
        self.assertEqual(value["package"]["fixed_zip_timestamp"], "1980-01-01T00:00:00")
        self.assertTrue(value["package"]["stable_entry_order"])
        for key in (
            "credential_bundle_contents_included",
            "worker_signing_bundle_contents_included",
            "release_private_key_included",
            "windows_lab_private_key_included",
        ):
            self.assertFalse(value["package"][key])
        for key in (
            "downloads_files",
            "extracts_existing_operation_package",
            "reads_historical_rc2_operation_package",
            "creates_virtual_machines",
            "creates_checkpoints",
            "restores_snapshots",
            "runs_authoritative_campaign",
            "authoritative",
            "ga_eligible",
        ):
            self.assertFalse(value["safety"][key])

    def test_zip_writer_is_byte_deterministic_and_order_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.zip"
            second = root / "second.zip"
            entries_a = [
                self.builder._zip_entry("z/data.txt", b"zeta\n"),
                self.builder._zip_entry("a/data.txt", b"alpha\n"),
                self.builder._zip_entry("operation-manifest.json", b"{}\n"),
            ]
            entries_b = list(reversed(entries_a))
            result_a = self.builder._write_deterministic_zip(first, entries_a)
            result_b = self.builder._write_deterministic_zip(second, entries_b)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(result_a["sha256"], result_b["sha256"])
            self.assertEqual(result_a["size"], result_b["size"])
            self.assertEqual(result_a["entries"], result_b["entries"])

            with zipfile.ZipFile(first, "r") as archive:
                names = [item.filename for item in archive.infolist()]
                self.assertEqual(names, sorted(names, key=str.casefold))
                for item in archive.infolist():
                    self.assertEqual(item.date_time, (1980, 1, 1, 0, 0, 0))

    def test_private_key_markers_are_rejected_before_zip_write(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Private-key material"):
            self.builder._zip_entry(
                "forbidden.pem",
                b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n",
            )

    def test_release_binding_is_canonical_and_complete(self) -> None:
        artifacts = {
            "source": {
                "name": "psmatrix-2.0.0rc3-source.zip",
                "sha256": "1" * 64,
                "size": 1,
            },
            "workers": {
                "name": "psmatrix-2.0.0rc3-windows-workers.zip",
                "sha256": "2" * 64,
                "size": 2,
            },
            "cert": {
                "name": "psmatrix-2.0.0rc3-windows-certification-kit.zip",
                "sha256": "3" * 64,
                "size": 3,
            },
            "prov": {
                "name": "psmatrix-2.0.0rc3-windows-provisioning-kit.zip",
                "sha256": "4" * 64,
                "size": 4,
            },
        }
        first = self.builder._release_binding(
            release_commit="a" * 40,
            release_manifest_sha256="5" * 64,
            artifacts=artifacts,
            media_manifest_sha256="6" * 64,
        )
        second = self.builder._release_binding(
            release_commit="a" * 40,
            release_manifest_sha256="5" * 64,
            artifacts=dict(reversed(list(artifacts.items()))),
            media_manifest_sha256="6" * 64,
        )
        self.assertEqual(first, second)
        self.assertTrue(first["valid"])
        self.assertEqual(first["source_sha256"], "1" * 64)
        self.assertEqual(first["windows_workers_sha256"], "2" * 64)
        self.assertEqual(first["windows_certification_kit_sha256"], "3" * 64)
        self.assertEqual(first["windows_provisioning_kit_sha256"], "4" * 64)
        self.assertEqual(first["release_manifest_sha256"], "5" * 64)
        self.assertEqual(first["windows_lab_media_sha256"], "6" * 64)
        self.assertRegex(first["binding_sha256"], r"^[0-9a-f]{64}$")

    def test_builder_reverifies_release_and_never_reuses_rc2_package(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "verify_release_manifest",
            "RELEASE_CLOSURE_READY",
            "release_authority_status",
            "ready_for_hyper_v_provisioning",
            "windows-authority-media-inventory.canonical.json",
            "windows-lab-media.json",
            "signed_artifacts != locked_artifacts",
            "_write_deterministic_zip",
            "_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)",
            "psmatrix.windows-authoritative-operation-package",
            "READY_FOR_WINDOWS_HOST",
            "stale_rc2_operation_package_used\": False",
            "credential_bundle_contents_included\": False",
            "worker_signing_bundle_contents_included\": False",
            "authoritative_campaign_executed\": False",
            "production_ga_gate\": \"INCOMPLETE\"",
            "ga_eligible\": False",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "release-assets/2.0.0rc2",
            "release-assets\\2.0.0rc2",
            "psmatrix-2.0.0rc2-windows-authoritative-operation",
            "requests.get(",
            "urllib.request",
            "Invoke-WebRequest",
            ".extractall(",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "authoritative\": True",
            "ga_eligible\": True",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
