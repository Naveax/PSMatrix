from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_VERIFY_SCRIPT = ROOT / "scripts" / "ga" / "verify_public_auth_cross_gate_bundles.py"
OTLP_VERIFY_SCRIPT = ROOT / "scripts" / "ga" / "verify_external_otlp_bundle.py"
PUBLIC_BIND_CONTENT_SCRIPT = ROOT / "scripts" / "ga" / "bind_public_auth_evidence_content.py"
PUBLIC_OPERATION_SCRIPT = ROOT / "scripts" / "ga" / "run_public_auth_evidence_content_operation.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class External22EvidencePathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_verify = load(PUBLIC_VERIFY_SCRIPT, "external22_public_verify_path_safety")
        cls.otlp_verify = load(OTLP_VERIFY_SCRIPT, "external22_otlp_verify_path_safety")
        cls.public_bind = load(PUBLIC_BIND_CONTENT_SCRIPT, "external22_public_content_bind_path_safety")
        cls.public_operation = load(PUBLIC_OPERATION_SCRIPT, "external22_public_content_operation_path_safety")

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

    def test_public_cross_gate_verify_rejects_direct_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-cross-root-symlink-") as temporary:
            root = Path(temporary)
            target = root / "oauth-target"
            target.mkdir()
            link = root / "oauth"
            self._symlink_or_skip(link, target, target_is_directory=True)
            contract = {
                "schema": 1,
                "kind": "psmatrix.final-deployment-evidence-producer-contract",
                "version": "2.0.0",
            }
            with self.assertRaisesRegex(
                self.public_verify.PublicAuthCrossGateError,
                "OAuth evidence root is missing or unsafe",
            ):
                self.public_verify.verify(link, target, contract)

    def test_external_otlp_bundle_verify_rejects_direct_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-bundle-root-symlink-") as temporary:
            root = Path(temporary)
            target = root / "bundle-target"
            target.mkdir()
            link = root / "bundle"
            self._symlink_or_skip(link, target, target_is_directory=True)
            release_key = root / "release-public.pem"
            release_key.write_text("not-used\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.otlp_verify.ExternalOTLPBundleError,
                "external OTLP bundle root is missing or unsafe",
            ):
                self.otlp_verify.verify(link, release_key, {})

    def test_external_otlp_bundle_verify_rejects_direct_release_key_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-otlp-release-key-symlink-") as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            key_target = root / "release-target.pem"
            key_target.write_text("not-used\n", encoding="utf-8")
            key_link = root / "release-public.pem"
            self._symlink_or_skip(key_link, key_target)
            with self.assertRaisesRegex(
                self.otlp_verify.ExternalOTLPBundleError,
                "release public key is missing or unsafe",
            ):
                self.otlp_verify.verify(bundle, key_link, {})

    def test_public_content_tree_state_rejects_direct_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-content-root-symlink-") as temporary:
            root = Path(temporary)
            target = root / "artifact-target"
            target.mkdir()
            (target / "sentinel.json").write_text("{}\n", encoding="utf-8")
            link = root / "artifact"
            self._symlink_or_skip(link, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.public_bind.PublicAuthContentBindingError,
                "materialized public-auth root is missing or unsafe",
            ):
                self.public_bind.tree_state(link)

    def test_public_content_operation_rejects_symlink_api_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-operation-api-symlink-") as temporary:
            root = Path(temporary)
            target = root / "api-target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "api.json"
            self._symlink_or_skip(link, target)
            workspace = root / "workspace"
            with self.assertRaisesRegex(
                self.public_operation.PublicAuthEvidenceContentOperationError,
                "evidence API verification is missing or unsafe",
            ):
                self.public_operation.run_operation(link, workspace, "Naveax/PSMatrix", "gh")
            self.assertFalse(workspace.exists())

    def test_public_content_operation_rejects_symlink_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-public-operation-workspace-symlink-") as temporary:
            root = Path(temporary)
            api = root / "api.json"
            api.write_text("{}\n", encoding="utf-8")
            target = root / "workspace-target"
            target.mkdir()
            workspace = root / "workspace"
            self._symlink_or_skip(workspace, target, target_is_directory=True)
            with self.assertRaisesRegex(
                self.public_operation.PublicAuthEvidenceContentOperationError,
                "public-auth evidence workspace is unsafe",
            ):
                self.public_operation.run_operation(api, workspace, "Naveax/PSMatrix", "gh")


if __name__ == "__main__":
    unittest.main()
