import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_rc4_operation_package.py"
LEGACY_BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_operation_package.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-operation-package-selfhosted.yml"
BUILDER_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-operation-package-builder-contract.json"
WORKFLOW_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-operation-package-workflow-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_rc4_operation_builder_test", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4OperationPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_historical_rc3_builder_remains_frozen_and_separate(self) -> None:
        text = LEGACY_BUILDER.read_text(encoding="utf-8")
        self.assertIn('source / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"', text)
        self.assertIn('version != "2.0.0rc3"', text)
        self.assertIn('description="Build a deterministic RC3 Windows operation package', text)
        self.assertNotIn("build_windows_authority_rc4_operation_package", text)

    def test_rc4_builder_contract_freezes_active_lock_and_schema2_intake(self) -> None:
        value = json.loads(BUILDER_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-operation-package-builder-contract")
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertNotIn("release_commit", value)
        req = value["input_requirements"]
        self.assertTrue(req["active_release_lock_required"])
        self.assertEqual(req["protected_release_intake_schema"], 2)
        self.assertTrue(req["reviewed_authority_rotation_required"])
        self.assertEqual(req["reviewed_authority_rotation_reason"], "lost_previous_private_authority")
        self.assertFalse(req["signing_time_authority_rotation"])
        self.assertTrue(req["signed_release_artifacts_must_equal_active_lock"])
        self.assertTrue(req["release_public_key_sha256_must_match_active_lock"])
        self.assertTrue(value["active_lock_binding"]["lock_sha256_required"])
        self.assertTrue(value["active_lock_binding"]["embedded_lock_required"])
        self.assertFalse(value["safety"]["creates_virtual_machines"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def test_rc4_workflow_contract_freezes_rebuild_and_disk_revalidation(self) -> None:
        value = json.loads(WORKFLOW_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["workflow"], "production-ga-windows-authority-rc4-operation-package-selfhosted")
        self.assertEqual(value["required_runner_labels"], ["self-hosted", "Windows", "X64", "psmatrix-hyperv"])
        self.assertEqual(value["prerequisites"]["protected_release_intake_schema"], 2)
        self.assertTrue(value["prerequisites"]["protected_release_intake_rotation_reviewed"])
        self.assertFalse(value["prerequisites"]["protected_release_intake_signing_time_rotation"])
        execution = value["execution"]
        for key in (
            "primary_build_required",
            "independent_rebuild_required",
            "byte_determinism_required",
            "active_lock_sha256_recomputed",
            "release_public_key_sha256_recomputed",
            "builder_revalidates_signed_release",
            "operation_package_binding_validator_required",
            "workflow_recomputes_provisioning_manifest_sha256",
            "workflow_recomputes_selection_sha256",
            "workflow_recomputes_profile_sha256",
            "workflow_recomputes_materialization_report_sha256",
            "workflow_recomputes_canonical_inventory_sha256",
            "workflow_requires_profile_under_ga_root",
            "workflow_revalidates_active_lock_binding",
            "workflow_revalidates_metadata_provisioning_binding",
            "workflow_revalidates_release_binding_against_disk",
            "ready_for_release_artifact_recovery_required",
            "run_attempt_scoped_output",
        ):
            self.assertTrue(execution[key])
        self.assertFalse(execution["overwrite_existing_output"])
        self.assertFalse(value["safety"]["operation_package_uploaded"])
        self.assertFalse(value["safety"]["creates_virtual_machines"])
        self.assertFalse(value["safety"]["ga_eligible"])

    def _lock(self, commit: str) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.windows-authority-release-staging-lock",
            "pack": "03-authoritative-windows",
            "version": "2.0.0rc4",
            "release_commit": commit,
            "authority_rotation": {
                "reason": "lost_previous_private_authority",
                "existing_candidate_mutated": False,
                "new_candidate": True,
                "review_required": True,
            },
            "release_public_key": {"sha256": "a" * 64},
            "artifacts": [{"name": "placeholder.zip", "sha256": "b" * 64, "size": 1}],
        }

    def test_rc4_lock_resolution_is_exact_checkout_bound_and_rotation_bound(self) -> None:
        commit = "c" * 40
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-operation-lock-") as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            lock = source / "rc4-release-lock.json"
            lock.write_text(json.dumps(self._lock(commit)), encoding="utf-8")
            resolved, value = self.builder._resolve_rc4_lock(source, lock, commit)
            self.assertEqual(resolved, lock.resolve())
            self.assertEqual(value["authority_rotation"]["reason"], "lost_previous_private_authority")

            outside = root / "outside.json"
            outside.write_text(json.dumps(self._lock(commit)), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "inside the exact source checkout"):
                self.builder._resolve_rc4_lock(source, outside, commit)

            bad = self._lock(commit)
            bad["authority_rotation"]["review_required"] = False
            lock.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "authority-rotation field review_required"):
                self.builder._resolve_rc4_lock(source, lock, commit)

    def test_rc4_schema2_intake_validation_is_reviewed_rotation_and_selected_manifest_bound(self) -> None:
        commit = "d" * 40
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-operation-intake-") as temp:
            root = Path(temp)
            source = root / "source"
            ga = root / "ga"
            release_root = ga / "media" / "release" / "2.0.0rc4"
            source.mkdir(); release_root.mkdir(parents=True)
            lock_path = source / "rc4-release-lock.json"
            lock = self._lock(commit)
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            manifest = release_root / "psmatrix-2.0.0rc4-release.json"
            manifest.write_text("{}\n", encoding="utf-8")
            report = {
                "schema": 2,
                "kind": "psmatrix.windows-authority-protected-release-intake",
                "status": "RELEASE_CLOSURE_READY",
                "version": "2.0.0rc4",
                "release_commit": commit,
                "release_lock_path": str(lock_path),
                "bundle_input_kind": "directory",
                "imported_release_root": str(release_root),
                "release_authority_status": "READY",
                "selected_manifest_path": str(manifest),
                "selected_manifest_sha256": self.builder.legacy.sha256_file(manifest),
                "ready_for_release_artifact_recovery": True,
                "broad_downloads_search_used": False,
                "private_key_material_absent": True,
                "release_authority_rotated": False,
                "release_authority_rotation_reviewed": True,
                "release_authority_rotation_reason": "lost_previous_private_authority",
                "release_authority_rotated_during_signing": False,
                "stale_rc2_operation_package_used": False,
                "media_manifest_materialized": False,
                "operation_package_rebuilt": False,
                "creates_virtual_machines": False,
                "creates_checkpoints": False,
                "authoritative": False,
                "ga_eligible": False,
            }
            intake = ga / "windows-authority-protected-release-intake.json"
            intake.write_text(json.dumps(report), encoding="utf-8")
            value = self.builder._validate_rc4_intake(
                ga,
                lock_path=lock_path,
                lock=lock,
                release_root=release_root,
                release_commit=commit,
            )
            self.assertTrue(value["release_authority_rotation_reviewed"])

            report["release_authority_rotated_during_signing"] = True
            intake.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "release_authority_rotated_during_signing"):
                self.builder._validate_rc4_intake(
                    ga,
                    lock_path=lock_path,
                    lock=lock,
                    release_root=release_root,
                    release_commit=commit,
                )

    def test_rc4_builder_and_workflow_are_offline_fail_closed_and_private_key_free(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "--release-lock",
            "rc4-release-lock.json",
            "release_authority_rotation_reviewed",
            "release_authority_rotated_during_signing",
            "signed_artifacts != locked_artifacts",
            "release_lock_binding",
            '"controller/rc4-release-lock.json"',
            "rc4-operation-package-builder-contract.json",
            "rc4-operation-package-workflow-contract.json",
            "rc4-provisioning-manifest-contract.json",
        ):
            with self.subTest(required=required):
                self.assertIn(required, builder)
        for required in (
            "production-ga-windows-authority-rc4-operation-package-selfhosted",
            "environment: production-ga-windows-lab",
            "Build primary deterministic RC4 operation package",
            "Rebuild independently and enforce RC4 byte determinism",
            "Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1",
            "release_lock_sha256",
            "Embedded RC4 release lock differs from current active lock",
            "Provisioning profile is missing or escapes the protected GA root",
            "windows-authority-rc4-operation-package",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        for text in (builder, workflow):
            for forbidden in (
                "PSMATRIX_RELEASE_PRIVATE_KEY",
                "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
                "psmatrix-2.0.0rc2-windows-authoritative-operation",
                "Invoke-WebRequest",
                "Start-BitsTransfer",
                "New-VM",
                "Checkpoint-VM",
                "Restore-VMSnapshot",
            ):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, text)

    def test_source_preflight_tracks_rc4_operation_package_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "ga-windows-authority-rc4-operation-package-selfhosted.yml",
            "build_windows_authority_rc4_operation_package.py",
            "rc4-operation-package-builder-contract.json",
            "rc4-operation-package-workflow-contract.json",
            "tests/test_windows_authority_rc4_operation_package.py",
            "tests.test_windows_authority_rc4_operation_package",
            "rc4_operation_package_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
