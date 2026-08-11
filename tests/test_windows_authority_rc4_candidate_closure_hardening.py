import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "ga" / "scan_private_key_material_streaming.py"
WRAPPER = ROOT / "scripts" / "ga" / "build_windows_authority_rc4_candidate_closure_hardened.py"
LEGACY = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-selfhosted.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-hardened-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-candidate-closure-hardening-workflow-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-hardening-source-preflight.yml"

def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path); assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class WindowsAuthorityRC4CandidateClosureHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.scanner = _load(SCANNER, "psmatrix_streaming_scan_test")

    def test_streaming_scanner_detects_marker_over_32mb_across_chunk_boundary(self):
        marker = b"-----BEGIN PRIVATE KEY-----"; mib = 1024 * 1024; boundary = 33 * mib
        with tempfile.TemporaryDirectory(prefix="psmatrix-large-private-") as temp:
            root = Path(temp); path = root / "evidence.bin"; start = boundary - len(marker) // 2
            with path.open("wb") as handle:
                handle.seek(start); handle.write(marker); handle.seek(boundary + mib - 1); handle.write(b"\0")
            self.assertGreater(path.stat().st_size, 32 * mib)
            with self.assertRaisesRegex(RuntimeError, "Private key material exists"): self.scanner.scan_tree(root)

    def test_streaming_scanner_has_no_size_limit_and_hashes_every_large_byte(self):
        mib = 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="psmatrix-large-clean-") as temp:
            root = Path(temp); path = root / "clean.bin"; size = 33 * mib + 123
            with path.open("wb") as handle: handle.seek(size - 1); handle.write(b"x")
            result = self.scanner.scan_tree(root)
            self.assertEqual(result["status"], "PASS"); self.assertFalse(result["size_limit_applied"])
            self.assertEqual(result["file_count"], 1); self.assertEqual(result["byte_count"], size)
            self.assertEqual(result["files"][0]["size"], size); self.assertRegex(result["tree_sha256"], r"^[0-9a-f]{64}$")

    def test_contract_requires_two_complete_stable_scans_bound_to_hardened_envelope(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8")); scan = value["private_key_rescan"]; closure = value["closure"]
        self.assertEqual(value["kind"], "psmatrix.windows-authority-rc4-candidate-closure-hardening-workflow-contract")
        for key in ("streaming","all_files","all_bytes","chunk_boundary_marker_detection","pre_scan_required","post_scan_required","tree_must_remain_stable","tree_sha256_bound_to_hardened_closure","scan_report_sha256_bound_to_hardened_closure"): self.assertTrue(scan[key])
        self.assertFalse(scan["size_limit_applied"]); self.assertEqual(closure["status"], "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING")
        self.assertTrue(closure["authoritative_windows"]); self.assertTrue(closure["release_bound"]); self.assertTrue(closure["final_release_required"])
        self.assertEqual(closure["final_release_version_required"], "2.0.0"); self.assertFalse(closure["final_ga_evaluator_invoked"]); self.assertFalse(closure["ga_eligible"])

    def test_legacy_path_is_disabled_sentinel_and_production_path_is_hardened(self):
        legacy = LEGACY.read_text(encoding="utf-8"); production = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: legacy-rc4-candidate-closure-source-contract-sentinel", legacy)
        self.assertIn("if: ${{ false }}", legacy); self.assertIn("intentionally disabled", legacy)
        self.assertIn("name: production-ga-windows-authority-rc4-candidate-closure-selfhosted", production)
        self.assertIn("build_windows_authority_rc4_candidate_closure_hardened.py", production)
        self.assertIn("Complete streaming private-key rescan did not PASS", production)
        self.assertIn("Campaign evidence tree changed during hardened closure", production)
        self.assertIn("hardened_campaign_evidence_bytes_scanned", production)
        for forbidden in ("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY","PSMATRIX_RELEASE_PRIVATE_KEY","python -m psmatrix.cli ga evaluate","New-VM","Checkpoint-VM"):
            self.assertNotIn(forbidden, production)

    def test_wrapper_binds_pre_post_tree_and_scan_report_without_final_ga_claim(self):
        text = WRAPPER.read_text(encoding="utf-8")
        for required in ("pre_scan = scanner.scan_tree(campaign)","post_scan = scanner.scan_tree(campaign)",'pre_scan["files"] != post_scan["files"]',"Campaign evidence tree changed during hardened candidate closure",'"campaign_streaming_private_key_rescan_sha256": scan_report_sha','"campaign_evidence_tree_sha256": post_scan["tree_sha256"]','"hardened_closure_sha256": hardened_sha','"final_ga_evaluator_invoked": False','"ga_eligible": False'):
            self.assertIn(required, text)

    def test_hardening_preflight_tracks_runtime_large_file_test(self):
        text = PREFLIGHT.read_text(encoding="utf-8")
        for required in ("scan_private_key_material_streaming.py","build_windows_authority_rc4_candidate_closure_hardened.py","ga-windows-authority-rc4-candidate-closure-hardened-selfhosted.yml","rc4-candidate-closure-hardening-workflow-contract.json","tests.test_windows_authority_rc4_candidate_closure_hardening","large_file_private_key_marker_detection=PASS","rc4_candidate_closure_hardening_contract=PASS"):
            self.assertIn(required, text)

if __name__ == "__main__": unittest.main()
