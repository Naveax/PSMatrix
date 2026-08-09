import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_provisioning_manifest.py"
WRAPPER = ROOT / "scripts" / "ga" / "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1"
RC3_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "provisioning-manifest-contract.json"
RC4_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-provisioning-manifest-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"
RC3_COMMIT = "34e87c60885001f8dd11744b8bf194a59e51bd1f"


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_rc4_provisioning_builder_test", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4ProvisioningManifestTests(unittest.TestCase):
    def test_historical_rc3_contract_remains_frozen(self) -> None:
        value = json.loads(RC3_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(value["release_commit"], RC3_COMMIT)
        self.assertTrue(value["rules"]["exact_release_commit_required"])

    def test_rc4_contract_is_version_frozen_but_commit_is_runtime_bound(self) -> None:
        value = json.loads(RC4_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-provisioning-manifest-contract")
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertNotIn("release_commit", value)
        self.assertEqual(value["release_commit_binding"], "active-rc4-release-lock-and-workflow-input")
        self.assertTrue(value["rules"]["exact_release_commit_required"])
        self.assertTrue(value["rules"]["release_commit_must_match_active_lock"])
        self.assertFalse(value["safety"]["creates_virtual_machines"])
        self.assertFalse(value["safety"]["creates_checkpoints"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_builder_keeps_rc3_default_and_allows_explicit_rc4_contract(self) -> None:
        module = _load_builder()
        path, contract, version = module.resolve_contract(ROOT, None, RC3_COMMIT)
        self.assertEqual(path, RC3_CONTRACT.resolve())
        self.assertEqual(contract["release_commit"], RC3_COMMIT)
        self.assertEqual(version, "2.0.0rc3")

        dynamic_commit = "a" * 40
        path, contract, version = module.resolve_contract(ROOT, RC4_CONTRACT, dynamic_commit)
        self.assertEqual(path, RC4_CONTRACT.resolve())
        self.assertNotIn("release_commit", contract)
        self.assertEqual(version, "2.0.0rc4")

        with self.assertRaisesRegex(RuntimeError, "frozen release commit"):
            module.resolve_contract(ROOT, None, "b" * 40)

    def test_builder_rejects_contract_outside_control_checkout(self) -> None:
        module = _load_builder()
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-provisioning-contract-") as temp:
            outside = Path(temp) / "contract.json"
            outside.write_text(RC4_CONTRACT.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "inside the control source checkout"):
                module.resolve_contract(ROOT, outside, "c" * 40)

    def test_builder_uses_contract_version_for_selection_and_report(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--contract", type=Path)', text)
        self.assertIn("contract_path, contract, release_version = resolve_contract", text)
        self.assertIn('selection.get("release_version") != release_version', text)
        self.assertIn('"release_version": release_version', text)
        self.assertIn('"contract_path": str(contract_path)', text)
        self.assertIn("exact_release_commit_required", text)
        self.assertNotIn('selection.get("release_version") != "2.0.0rc3"', text)
        self.assertNotIn('"release_version": "2.0.0rc3",\n        "release_commit": release_commit', text)

    def test_wrapper_passes_explicit_contract_without_changing_default(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("[string]$ContractPath = ''", text)
        self.assertIn("$arguments += @('--contract'", text)
        self.assertIn("--release-commit", text)

    def test_source_preflight_tracks_rc4_provisioning_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "rc4-provisioning-manifest-contract.json",
            "build_windows_authority_provisioning_manifest.py",
            "New-PSMatrixWindowsAuthorityProvisioningManifest.ps1",
            "tests/test_windows_authority_rc4_provisioning_manifest.py",
            "tests.test_windows_authority_rc4_provisioning_manifest",
            "rc4_provisioning_manifest_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
