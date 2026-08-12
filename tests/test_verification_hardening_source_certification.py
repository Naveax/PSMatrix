from __future__ import annotations

import importlib.util
from pathlib import Path

BASE = Path(__file__).with_name("_verification_hardening_source_certification_base.py")
spec = importlib.util.spec_from_file_location("verification_hardening_source_certification_base", BASE)
assert spec is not None and spec.loader is not None
_base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_base)


class VerificationHardeningSourceCertificationTests(
    _base.VerificationHardeningSourceCertificationTests
):
    def clean_scan(self) -> dict[str, object]:
        scanner = self.module._load_private_scanner()
        scanner.assert_clean_working_tree(self.root, "git")
        before = scanner.repository_head(self.root, "git")
        tree_before = scanner.repository_tree(self.root, "git", before)
        value = scanner.scan_git_head(self.root, "git", before)
        scanner.assert_clean_working_tree(self.root, "git")
        after = scanner.repository_head(self.root, "git")
        tree_after = scanner.repository_tree(self.root, "git", after)
        self.assertEqual(before, after)
        self.assertEqual(tree_before, tree_after)
        value["repository_head"] = after
        value["repository_tree"] = tree_after
        value["working_tree_clean_verified"] = True
        value["repository_head_stable_during_scan"] = True
        value["repository_tree_stable_during_scan"] = True
        value["expected_repository_head"] = after
        value["expected_repository_head_verified"] = True
        self.assertTrue(value["tracked_blob_authority_verified"])
        return value

    def test_git_blob_authority_proof_is_required(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py")
        for mode in ("missing", "false"):
            with self.subTest(mode=mode):
                scan = self.clean_scan()
                if mode == "missing":
                    scan.pop("tracked_blob_authority_verified")
                else:
                    scan["tracked_blob_authority_verified"] = False
                with self.assertRaises(self.module.HardeningSourceCertificationError):
                    self.module.certify(self.root, self.baseline, scan)

    def test_expected_head_proof_is_required_and_exact(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py")
        for mode in ("missing", "false", "wrong"):
            with self.subTest(mode=mode):
                scan = self.clean_scan()
                if mode == "missing":
                    scan.pop("expected_repository_head")
                elif mode == "false":
                    scan["expected_repository_head_verified"] = False
                else:
                    scan["expected_repository_head"] = "0" * 40
                with self.assertRaises(self.module.HardeningSourceCertificationError):
                    self.module.certify(self.root, self.baseline, scan)

    def test_pass_receipt_propagates_event_head_blob_and_tree_authority(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py", "print('safe')\n")
        value = self.module.certify(self.root, self.baseline, self.clean_scan())
        self.assertTrue(value["private_material_scan_expected_repository_head_verified"])
        self.assertEqual(
            value["private_material_scan_expected_repository_head"],
            self.git("rev-parse", "HEAD").strip().lower(),
        )
        self.assertTrue(value["private_material_scan_tracked_blob_authority_verified"])
        self.assertTrue(value["boundaries"]["private_material_scan_tracked_blob_authority_verified"])
        self.assertRegex(value["private_material_scan_repository_tree"], r"^[0-9a-f]{40}$")
        self.assertTrue(value["boundaries"]["private_material_scan_repository_tree_bound"])
        self.assertTrue(value["boundaries"]["private_material_scan_repository_tree_stable_during_scan"])

    def test_repository_source_freezes_event_head_blob_and_tree_authority_boundary(self) -> None:
        text = self.module.__file__ and Path(self.module.__file__).read_text(encoding="utf-8")
        self.assertIn("scan_git_head", text)
        self.assertIn("private_material_scan_expected_repository_head_verified", text)
        self.assertIn("private_material_scan_tracked_blob_authority_verified", text)
        self.assertIn("tracked_blob_authority_verified", text)
        self.assertIn("scanner.repository_tree", text)
        self.assertIn("private_material_scan_repository_tree", text)
