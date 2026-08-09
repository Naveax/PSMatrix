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
    spec = importlib.util.spec_from_file_location(
        "psmatrix_operation_package_builder_test", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load operation-package builder module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityOperationPackageBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_contract_requires_real_provisioning_manifest_closure(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-operation-package-builder-contract",
        )
        self.assertEqual(value["release_version"], "2.0.0rc3")
        requirements = value["input_requirements"]
        self.assertEqual(
            requirements["reviewed_release_lock_pack"], "03-authoritative-windows"
        )
        self.assertFalse(requirements["protected_release_intake_media_manifest_materialized"])
        self.assertFalse(requirements["protected_release_intake_operation_package_rebuilt"])
        self.assertEqual(
            requirements["selection_materialization_kind"],
            "psmatrix.windows-authority-media-selection-materialization",
        )
        self.assertEqual(
            requirements["provisioning_manifest_kind"], "psmatrix.windows-lab-media"
        )
        self.assertEqual(requirements["provisioning_materialization_status"], "PASS")
        self.assertEqual(requirements["provisioning_product_loader_validation"], "PASS")
        self.assertEqual(requirements["operation_package_handoff_validation"], "PASS")
        for key in (
            "selection_inventory_sha256_must_match_disk",
            "provisioning_manifest_sha256_must_match_materialization_report",
            "selection_sha256_must_match_materialization_report",
            "profile_sha256_must_match_materialization_report",
            "signed_release_manifest_reverified",
            "signed_release_artifacts_must_equal_reviewed_lock",
        ):
            self.assertTrue(requirements[key])
        for key in (
            "windows_lab_media_sha256",
            "windows_authority_media_selection_sha256",
            "provisioning_profile_sha256",
            "provisioning_materialization_report_sha256",
            "canonical_inventory_sha256",
            "canonical_binding_sha256",
        ):
            self.assertTrue(value["release_binding"][key])
        self.assertEqual(
            value["package"]["kind"],
            "psmatrix.windows-authoritative-operation-package",
        )
        self.assertEqual(value["package"]["status"], "READY_FOR_WINDOWS_HOST")
        self.assertTrue(value["package"]["deterministic_zip"])
        self.assertTrue(value["package"]["embeds_media_manifest_contract"])
        self.assertTrue(value["package"]["embeds_sanitized_provisioning_binding"])
        self.assertFalse(value["package"]["credential_bundle_contents_included"])
        self.assertFalse(value["package"]["worker_signing_bundle_contents_included"])
        self.assertFalse(value["safety"]["opens_credential_bundle"])
        self.assertFalse(value["safety"]["opens_worker_signing_bundle"])
        self.assertFalse(value["safety"]["reads_historical_rc2_operation_package"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

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
            self.assertEqual(result_a, result_b)
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

    def test_release_binding_covers_provisioning_handoff(self) -> None:
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
            selection_sha256="7" * 64,
            profile_sha256="8" * 64,
            materialization_report_sha256="9" * 64,
            canonical_inventory_sha256="a" * 64,
        )
        second = self.builder._release_binding(
            release_commit="a" * 40,
            release_manifest_sha256="5" * 64,
            artifacts=dict(reversed(list(artifacts.items()))),
            media_manifest_sha256="6" * 64,
            selection_sha256="7" * 64,
            profile_sha256="8" * 64,
            materialization_report_sha256="9" * 64,
            canonical_inventory_sha256="a" * 64,
        )
        self.assertEqual(first, second)
        self.assertTrue(first["valid"])
        self.assertEqual(first["windows_lab_media_sha256"], "6" * 64)
        self.assertEqual(first["windows_authority_media_selection_sha256"], "7" * 64)
        self.assertEqual(first["provisioning_profile_sha256"], "8" * 64)
        self.assertEqual(first["provisioning_materialization_report_sha256"], "9" * 64)
        self.assertEqual(first["canonical_inventory_sha256"], "a" * 64)
        self.assertRegex(first["binding_sha256"], r"^[0-9a-f]{64}$")

    def test_builder_revalidates_new_handoff_and_never_reuses_rc2(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "verify_release_manifest",
            "RELEASE_CLOSURE_READY",
            '"media_manifest_materialized": False',
            '"operation_package_rebuilt": False',
            'lock.get("pack") != "03-authoritative-windows"',
            "psmatrix.windows-authority-media-selection-materialization",
            "psmatrix.windows-lab-media",
            "windows-authority-provisioning-manifest-materialization",
            "operation_package_handoff_validation",
            "selection_manifest_sha256",
            "profile_sha256",
            "manifest_sha256",
            "windows-authority-media-selection.json",
            "windows-lab-media.json",
            '"controller/media-manifest-contract.json"',
            "signed_artifacts != locked_artifacts",
            "_write_deterministic_zip",
            "_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)",
            '"provisioning_manifest": {',
            '"selection_sha256": selection_sha',
            '"profile_sha256": profile_sha',
            '"stale_rc2_operation_package_used": False',
            '"production_ga_gate": "INCOMPLETE"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
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
            '"authoritative": True',
            '"ga_eligible": True',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
