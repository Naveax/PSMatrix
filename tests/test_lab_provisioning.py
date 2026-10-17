import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.lab_certification import load_fixture_pack
from psmatrix.lab_provisioning import (
    AuthoritativeMatrixSpec,
    LabProvisioningError,
    WindowsLabManifest,
    build_provision_plan,
    build_provisioning_kit,
    build_windows_release_binding,
    create_authoritative_matrix_attestation,
    lab_profiles,
    verify_authoritative_matrix_attestation,
    verify_provisioning_kit,
)
from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair
from psmatrix.util import sha256_file


class LabProvisioningTests(unittest.TestCase):
    def _artifact(self, root: Path, name: str) -> dict:
        path = root / name
        path.write_bytes((name + "\n").encode())
        return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}

    def _release_binding(self, root: Path, private: Path, public: Path) -> dict:
        artifacts = []
        for name in (
            "psmatrix-2.0.0-source.zip",
            "psmatrix-2.0.0-py3-none-any.whl",
            "psmatrix-2.0.0-windows-workers.zip",
            "psmatrix-2.0.0-windows-certification-kit.zip",
            "psmatrix-2.0.0-windows-provisioning-kit.zip",
        ):
            path = root / name
            path.write_bytes((name + "\n").encode())
            artifacts.append(path)
        manifest = root / "psmatrix-2.0.0-release.json"
        create_release_manifest(
            artifacts, manifest, version="2.0.0",
            signing_private_key=private, signing_public_key=public,
        )
        return build_windows_release_binding(
            release_manifest=manifest, artifact_dir=root, release_public_key=public,
            release_commit="1" * 40, output=root / "release-binding.json",
        )

    def _manifest(self, root: Path, *, omit_wmf: bool = False) -> Path:
        common = {
            "source_iso": self._artifact(root, "windows.iso"),
            "worker_package": self._artifact(root, "worker.zip"),
            "python_installer": self._artifact(root, "python.exe"),
            "credential_bundle": self._artifact(root, "credentials.zip"),
            "signing_bundle": self._artifact(root, "signing.zip"),
        }
        images = []
        for index, version in enumerate(("4.0", "5.0", "5.1"), start=1):
            item = {
                "runtime_id": "windows-powershell-" + version,
                "image_id": "psmatrix-" + version.replace(".", ""),
                "worker_id": "worker-" + version.replace(".", ""),
                "computer_name": "PSMATRIX" + version.replace(".", ""),
                "output_vhdx": "C:\\PSMatrix\\" + version + ".vhdx",
                "edition_index": index,
                "expected_os": {"product_name": "Windows Server", "version": "6.3", "build": "9600"},
                "admin_password_env": "PSMATRIX_LAB_PASSWORD_" + version.replace(".", ""),
                **common,
            }
            if version == "5.0" and not omit_wmf:
                item["wmf_package"] = self._artifact(root, "wmf5.msu")
            images.append(item)
        value = {
            "schema": 1,
            "kind": "psmatrix.windows-lab-media",
            "hyperv_host": {"host_id": "hyperv-lab-01", "lab_root": "C:\\PSMatrix"},
            "defaults": {"switch_name": "PSMatrix-Lab", "checkpoint_name": "psmatrix-clean"},
            "images": images,
        }
        path = root / "windows-lab-media.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_evaluation_media_template_matches_standard_gui_image_selection(self):
        """Keep the operator example consistent with Server 2012 R2/2016 eval ISO WIM indexes."""
        source = Path(__file__).resolve().parents[1]
        template_path = source / "examples" / "windows-lab-media.template.json"
        value = json.loads(template_path.read_text(encoding="utf-8"))
        images = value["images"]
        self.assertEqual(
            [image["runtime_id"] for image in images],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        )
        expected = {
            "windows-powershell-4.0": ("Microsoft Windows Server 2012 R2 Standard Evaluation", "6.3.9600", "9600"),
            "windows-powershell-5.0": ("Microsoft Windows Server 2012 R2 Standard Evaluation", "6.3.9600", "9600"),
            "windows-powershell-5.1": ("Microsoft Windows Server 2016 Standard Evaluation", "10.0.14393", "14393"),
        }
        for image in images:
            with self.subTest(runtime=image["runtime_id"]):
                self.assertEqual(image["edition_index"], 2)  # Standard Evaluation with GUI/Desktop Experience
                expected_os = image["expected_os"]
                self.assertEqual(
                    (expected_os["product_name"], expected_os["version"], expected_os["build"]),
                    expected[image["runtime_id"]],
                )
                self.assertTrue(image["worker_package"]["path"].endswith("psmatrix-2.0.0-windows-workers.zip"))
                # This is an illustrative template, never a runnable artifact without real SHA-256 bindings.
                for kind in ("source_iso", "worker_package", "python_installer", "credential_bundle", "signing_bundle"):
                    self.assertEqual(image[kind]["sha256"], "REPLACE_64_HEX")
        self.assertEqual(images[1]["wmf_package"]["sha256"], "REPLACE_64_HEX")
        with self.assertRaises(LabProvisioningError):
            WindowsLabManifest.load(template_path)

    def test_profiles_cover_exact_historical_windows_runtimes(self):
        value = lab_profiles()
        self.assertEqual(
            {item["runtime_id"] for item in value["profiles"]},
            {"windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"},
        )

    def test_manifest_and_plan_are_exact_and_secret_free(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self._manifest(root)
            manifest = WindowsLabManifest.load(path)
            self.assertEqual(len(manifest.images), 3)
            output = root / "plan.json"
            plan = build_provision_plan(path, output=output)
            self.assertEqual(plan["kind"], "psmatrix.windows-hyperv-provision-plan")
            self.assertEqual(len(plan["images"]), 3)
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("password_value", text)
            self.assertIn("admin_password_env", text)

    def test_powershell_50_requires_exact_offline_wmf_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(LabProvisioningError):
                WindowsLabManifest.load(self._manifest(root, omit_wmf=True))

    def test_provisioning_kit_is_reproducible_signed_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = Path(__file__).resolve().parents[1]
            plan = root / "plan.json"
            build_provision_plan(self._manifest(root), output=plan)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            first = root / "first.zip"
            second = root / "second.zip"
            one = build_provisioning_kit(source, first, version="1.3.0", plan_path=plan, signing_private_key=private, signing_public_key=public)
            two = build_provisioning_kit(source, second, version="1.3.0", plan_path=plan, signing_private_key=private, signing_public_key=public)
            self.assertEqual(one["sha256"], two["sha256"])
            verified = verify_provisioning_kit(first, signing_public_key=public)
            self.assertTrue(verified["valid"] and verified["signed"])
            with zipfile.ZipFile(first, "a") as archive:
                archive.writestr("undeclared.txt", b"tamper")
            with self.assertRaises(LabProvisioningError):
                verify_provisioning_kit(first, signing_public_key=public)

    def test_authoritative_fixture_pack_has_extended_capabilities(self):
        source = Path(__file__).resolve().parents[1]
        pack = load_fixture_pack(source / "fixtures" / "windows-authoritative")
        required = {"scheduled-tasks", "ntfs-acl", "certificates", "process"}
        self.assertTrue(required.issubset(set(pack["manifest"]["capabilities"])))

    def test_authoritative_matrix_attestation_roundtrip_and_incomplete_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            campaigns = [
                {"runtime_id": runtime, "valid": True, "run_count": 3, "campaign_sha256": "a" * 64, "image_manifest_sha256": "b" * 64}
                for runtime in ("windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1")
            ]
            binding = self._release_binding(root, private, public)
            envelope = create_authoritative_matrix_attestation(
                matrix_id="matrix-1", campaigns=campaigns, private_key=private, public_key=public,
                release_binding=binding,
            )
            path = root / "matrix.json"
            path.write_text(json.dumps(envelope), encoding="utf-8")
            result = verify_authoritative_matrix_attestation(path, public_key=public)
            self.assertTrue(result["valid"])
            self.assertEqual(result["campaign_count"], 3)
            self.assertTrue(result["release_bound"])
            self.assertEqual(result["release_binding"]["release_commit"], "1" * 40)
            with self.assertRaises(LabProvisioningError):
                create_authoritative_matrix_attestation(matrix_id="bad", campaigns=campaigns[:2], private_key=private, public_key=public)

    def test_release_binding_requires_signed_complete_windows_artifact_set(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            binding = self._release_binding(root, private, public)
            self.assertEqual(binding["release_version"], "2.0.0")
            self.assertEqual(binding["release_commit"], "1" * 40)
            self.assertEqual(len(binding["binding_sha256"]), 64)
            broken = json.loads((root / "release-binding.json").read_text())
            broken["windows_workers"]["sha256"] = "0" * 64
            (root / "release-binding-broken.json").write_text(json.dumps(broken), encoding="utf-8")
            from psmatrix.lab_provisioning import load_windows_release_binding
            with self.assertRaises(LabProvisioningError):
                load_windows_release_binding(root / "release-binding-broken.json")

    def test_v1_matrix_remains_verifiable_but_is_not_release_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            campaigns = [
                {"runtime_id": runtime, "valid": True, "run_count": 2, "campaign_sha256": "a" * 64, "image_manifest_sha256": "b" * 64}
                for runtime in ("windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1")
            ]
            envelope = create_authoritative_matrix_attestation(
                matrix_id="legacy", campaigns=campaigns, private_key=private, public_key=public,
            )
            path = root / "legacy.json"
            path.write_text(json.dumps(envelope), encoding="utf-8")
            result = verify_authoritative_matrix_attestation(path, public_key=public)
            self.assertTrue(result["valid"])
            self.assertFalse(result["release_bound"])

    def test_matrix_spec_requires_three_unique_exact_runtimes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "fixtures"
            fixture.mkdir()
            endpoint = root / "endpoint.json"; endpoint.write_text("{}", encoding="utf-8")
            image = root / "image.json"; image.write_text("{}", encoding="utf-8")
            value = {
                "schema": 1, "kind": "psmatrix.windows-authoritative-matrix", "matrix_id": "matrix", "iterations": 3,
                "targets": [
                    {"runtime_id": "windows-powershell-4.0", "endpoint": "endpoint.json", "image_manifest": "image.json", "fixture_root": "fixtures"},
                    {"runtime_id": "windows-powershell-5.0", "endpoint": "endpoint.json", "image_manifest": "image.json", "fixture_root": "fixtures"},
                    {"runtime_id": "windows-powershell-5.1", "endpoint": "endpoint.json", "image_manifest": "image.json", "fixture_root": "fixtures"},
                ],
            }
            path = root / "matrix.json"; path.write_text(json.dumps(value), encoding="utf-8")
            spec = AuthoritativeMatrixSpec.load(path)
            self.assertEqual(len(spec.targets), 3)


if __name__ == "__main__":
    unittest.main()
