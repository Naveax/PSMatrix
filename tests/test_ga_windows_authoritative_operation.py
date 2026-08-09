import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.lab_provisioning import LabProvisioningError
from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair
from psmatrix.windows_authority import (
    build_windows_release_binding,
    create_authoritative_matrix_attestation,
    verify_authoritative_matrix_attestation,
)


class GAWindowsAuthoritativeOperationTests(unittest.TestCase):
    def _release(self, root: Path):
        release_private = root / "release-private.pem"
        release_public = root / "release-public.pem"
        generate_ed25519_keypair(release_private, release_public)
        artifacts = []
        for name, payload in (
            ("psmatrix-2.0.0-source.zip", b"source"),
            ("psmatrix-2.0.0.whl", b"wheel"),
            ("psmatrix-2.0.0-windows-workers.zip", b"workers"),
            ("psmatrix-2.0.0-windows-certification-kit.zip", b"certification"),
            ("psmatrix-2.0.0-windows-provisioning-kit.zip", b"provisioning"),
        ):
            path = root / name
            path.write_bytes(payload)
            artifacts.append(path)
        manifest = root / "release.json"
        create_release_manifest(
            artifacts,
            manifest,
            version="2.0.0",
            signing_private_key=release_private,
            signing_public_key=release_public,
        )
        return release_private, release_public, manifest

    @staticmethod
    def _campaigns():
        return [
            {
                "runtime_id": "windows-powershell-4.0",
                "status": "PASS",
                "authoritative": True,
                "worker": {"os": "Windows", "edition": "Desktop", "version": "4.0"},
                "snapshot_reset": {"before": {"passed": True}, "after": {"passed": True}},
            },
            {
                "runtime_id": "windows-powershell-5.0",
                "status": "PASS",
                "authoritative": True,
                "worker": {"os": "Windows", "edition": "Desktop", "version": "5.0"},
                "snapshot_reset": {"before": {"passed": True}, "after": {"passed": True}},
            },
            {
                "runtime_id": "windows-powershell-5.1",
                "status": "PASS",
                "authoritative": True,
                "worker": {"os": "Windows", "edition": "Desktop", "version": "5.1"},
                "snapshot_reset": {"before": {"passed": True}, "after": {"passed": True}},
            },
        ]

    def test_layout_and_documentation_exist_and_are_secret_free(self):
        root = Path(__file__).resolve().parents[1]
        expected = [
            root / "ga-packs" / "03-authoritative-windows" / "README.md",
            root / "ga-packs" / "03-authoritative-windows" / "operation-contract.json",
            root / "ga-packs" / "03-authoritative-windows" / "windows-lab-media.example.json",
            root / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1",
            root / ".github" / "workflows" / "ga-windows-authoritative-selfhosted.yml",
        ]
        for path in expected:
            self.assertTrue(path.is_file(), path)
        combined = "\n".join(path.read_text(encoding="utf-8") for path in expected)
        self.assertNotIn("BEGIN PRIVATE KEY", combined)
        self.assertIn("release commit", combined.lower())

    def test_operator_script_requires_release_binding_and_exact_runtime_set(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1").read_text(encoding="utf-8")
        for required in (
            "windows-powershell-4.0",
            "windows-powershell-5.0",
            "windows-powershell-5.1",
            "release_commit",
            "release_manifest_sha256",
            "source_sha256",
            "windows_workers_sha256",
            "windows_certification_kit_sha256",
            "windows_provisioning_kit_sha256",
        ):
            self.assertIn(required, script)

    def test_workflow_is_manual_protected_self_hosted_and_sha_pinned(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "ga-windows-authoritative-selfhosted.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("self-hosted", workflow)
        self.assertIn("environment: production-ga-windows-lab", workflow)
        self.assertIn("release_commit:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertNotIn("actions/checkout@v", workflow)
        self.assertNotIn("actions/setup-python@v", workflow)

    def test_release_binding_rejects_missing_windows_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            source = root / "psmatrix-2.0.0-source.zip"
            wheel = root / "psmatrix-2.0.0.whl"
            source.write_bytes(b"source")
            wheel.write_bytes(b"wheel")
            manifest = root / "release.json"
            create_release_manifest(
                [source, wheel], manifest, version="2.0.0",
                signing_private_key=private, signing_public_key=public,
            )
            with self.assertRaises(LabProvisioningError):
                build_windows_release_binding(
                    release_manifest=manifest,
                    artifact_dir=root,
                    release_public_key=public,
                    release_commit="a" * 40,
                )

    def test_v2_matrix_subject_binds_release_artifacts_and_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release_private, release_public, manifest = self._release(root)
            binding = build_windows_release_binding(
                release_manifest=manifest,
                artifact_dir=root,
                release_public_key=release_public,
                release_commit="a" * 40,
                output=root / "binding.json",
            )
            lab_private = root / "lab.private.pem"
            lab_public = root / "lab.public.pem"
            generate_ed25519_keypair(lab_private, lab_public)
            envelope = create_authoritative_matrix_attestation(
                matrix_id="ga-windows",
                campaigns=self._campaigns(),
                private_key=lab_private,
                public_key=lab_public,
                release_binding=binding,
            )
            path = root / "windows.dsse.json"
            path.write_text(json.dumps(envelope), encoding="utf-8")
            verified = verify_authoritative_matrix_attestation(path, public_key=lab_public)
            self.assertTrue(verified["release_bound"])
            self.assertEqual(
                verified["release_binding"]["release_manifest_sha256"],
                binding["release_manifest_sha256"],
            )
            tampered = json.loads(path.read_text())
            signature = str(tampered["signatures"][0]["sig"])
            self.assertTrue(signature)
            replacement = "B" if signature[0] == "A" else "A"
            tampered["signatures"][0]["sig"] = replacement + signature[1:]
            self.assertNotEqual(tampered["signatures"][0]["sig"], signature)
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(Exception):
                verify_authoritative_matrix_attestation(path, public_key=lab_public)


if __name__ == "__main__":
    unittest.main()
