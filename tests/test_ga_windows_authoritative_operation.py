from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from psmatrix.ga import evaluate_ga
from psmatrix.lab_provisioning import (
    LabProvisioningError,
    build_windows_release_binding,
    create_authoritative_matrix_attestation,
    verify_authoritative_matrix_attestation,
)
from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authoritative.yml"
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1"
DOC = ROOT / "docs" / "PRODUCTION_GA_WINDOWS.md"
LAYOUT = ROOT / "ops" / "windows-ga" / "windows-ga-layout.template.json"


class GAWindowsAuthoritativeOperationTests(unittest.TestCase):
    def _release(self, root: Path):
        private = root / "release.private.pem"
        public = root / "release.public.pem"
        generate_ed25519_keypair(private, public)
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
            artifacts,
            manifest,
            version="2.0.0",
            signing_private_key=private,
            signing_public_key=public,
        )
        return private, public, manifest

    def _campaigns(self):
        return [
            {
                "runtime_id": runtime,
                "valid": True,
                "run_count": 10,
                "campaign_sha256": char * 64,
                "image_manifest_sha256": (char.upper().lower()) * 64,
            }
            for runtime, char in (
                ("windows-powershell-4.0", "a"),
                ("windows-powershell-5.0", "b"),
                ("windows-powershell-5.1", "c"),
            )
        ]

    def test_workflow_is_manual_protected_self_hosted_and_sha_pinned(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("push:", text)
        self.assertIn("environment: production-ga-windows-lab", text)
        self.assertIn("runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("provision:", text)
        self.assertIn("default: false", text)
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses), 3)
        for value in uses:
            self.assertRegex(value, r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$", value)

    def test_operator_script_requires_release_binding_and_exact_runtime_set(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("lab', 'release-binding'", text)
        self.assertIn("--release-binding", text)
        self.assertIn("lab', 'authoritative-matrix'", text)
        self.assertIn("lab', 'verify-authoritative-matrix'", text)
        for runtime in ("windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"):
            self.assertIn(runtime, text)
        self.assertIn("Output directory must be empty", text)
        self.assertNotIn("LabPrivateKey = (Join-Path $output", text)

    def test_layout_and_documentation_exist_and_are_secret_free(self):
        layout = json.loads(LAYOUT.read_text(encoding="utf-8"))
        self.assertEqual(layout["kind"], "psmatrix.windows-ga-runner-layout")
        self.assertIn("windows-lab-media.json", "\n".join(layout["required"]["config"]))
        combined = LAYOUT.read_text(encoding="utf-8") + DOC.read_text(encoding="utf-8")
        self.assertNotIn("BEGIN PRIVATE KEY", combined)
        self.assertIn("release commit", combined.lower())

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
            self.assertEqual(verified["release_binding"]["release_manifest_sha256"], binding["release_manifest_sha256"])
            tampered = json.loads(path.read_text())
            statement_payload = tampered["payload"]
            self.assertIsInstance(statement_payload, str)
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
