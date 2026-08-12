from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_final_ga_attestation_public_asset.py"
VERIFIER = ROOT / "scripts" / "ga" / "verify_final_ga_attestation_public_asset.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAPublicAssetIOSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load(BUILDER, "final_ga_public_asset_builder_io")
        self.verifier = load(VERIFIER, "final_ga_public_asset_verifier_io")

    def test_builder_receipt_writer_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            path.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(self.builder.FinalGAAttestationPublicAssetError):
                self.builder._write_json_once(path, {"status": "PASS"}, "receipt")
            self.assertEqual(path.read_text(encoding="utf-8"), "sentinel\n")

    def test_verifier_output_writer_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "verification.json"
            path.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
                self.verifier._write_json_once(path, {"status": "PASS"})
            self.assertEqual(path.read_text(encoding="utf-8"), "sentinel\n")

    def test_both_writers_require_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(self.builder.FinalGAAttestationPublicAssetError):
                self.builder._write_json_once(root / "missing-a" / "receipt.json", {"status": "PASS"}, "receipt")
            with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
                self.verifier._write_json_once(root / "missing-b" / "verification.json", {"status": "PASS"})

    def test_both_writers_round_trip_exact_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            builder_path = root / "builder.json"
            verifier_path = root / "verifier.json"
            self.builder._write_json_once(builder_path, {"status": "PASS", "count": 9}, "receipt")
            self.verifier._write_json_once(verifier_path, {"status": "PASS", "count": 9})
            self.assertEqual(json.loads(builder_path.read_text(encoding="utf-8")), {"status": "PASS", "count": 9})
            self.assertEqual(json.loads(verifier_path.read_text(encoding="utf-8")), {"status": "PASS", "count": 9})

    def test_builder_json_reader_rejects_parent_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            (real / "operation.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
            alias = root / "alias"
            try:
                os.symlink(real, alias, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable")
            with self.assertRaises(self.builder.FinalGAAttestationPublicAssetError):
                self.builder._safe_json(alias / "operation.json", "operation")

    def test_verifier_json_reader_rejects_leaf_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "receipt.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            link = root / "link.json"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(self.verifier.FinalGAAttestationPublicAssetVerificationError):
                self.verifier._json(link, "receipt")

    def test_source_freezes_exclusive_receipt_and_verification_output_contract(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        verifier = VERIFIER.read_text(encoding="utf-8")
        for text in (builder, verifier):
            self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", text)
            self.assertIn("os.fsync", text)
            self.assertIn("os.fstat", text)
            self.assertIn("read-back mismatch", text)
        self.assertNotIn("args.receipt.parent.mkdir", builder)
        self.assertNotIn("args.receipt.write_text", builder)
        self.assertNotIn("args.output.parent.mkdir", verifier)
        self.assertNotIn("args.output.write_text", verifier)


if __name__ == "__main__":
    unittest.main()
