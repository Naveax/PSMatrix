from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "run_final_attestation_content_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_attestation_content_operation_io", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalAttestationContentOperationIOSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_json_reader_accepts_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            path.write_text('{"status":"PASS"}\n', encoding="utf-8")
            self.assertEqual(
                self.module._read_json_object(path, label="receipt"),
                {"status": "PASS"},
            )

    def test_json_reader_rejects_leaf_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            link = root / "link.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._read_json_object(link, label="receipt")

    def test_json_reader_rejects_parent_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            (real / "receipt.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
            alias = root / "alias"
            try:
                os.symlink(real, alias, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable")
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._read_json_object(alias / "receipt.json", label="receipt")

    def test_write_once_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            path.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._write_json_once(path, {"status": "PASS"}, label="receipt")
            self.assertEqual(path.read_text(encoding="utf-8"), "sentinel\n")

    def test_write_once_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "missing" / "receipt.json"
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._write_json_once(path, {"status": "PASS"}, label="receipt")
            self.assertFalse(path.exists())

    def test_write_once_round_trips_exact_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            written = self.module._write_json_once(path, {"status": "PASS", "value": 7}, label="receipt")
            self.assertEqual(written, path.resolve())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"status": "PASS", "value": 7})

    def test_external_workspace_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "missing-parent" / "workspace"
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._external_workspace(path)

    def test_external_workspace_is_created_once_under_safe_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "workspace"
            result = self.module._external_workspace(path)
            self.assertEqual(result, path.resolve())
            self.assertTrue(result.is_dir())
            (result / "occupied").write_text("x", encoding="utf-8")
            with self.assertRaises(self.module.FinalAttestationContentOperationError):
                self.module._external_workspace(path)

    def test_source_freezes_exclusive_fsync_identity_and_readback_contract(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("os.fstat", text)
        self.assertIn("candidate.lstat()", text)
        self.assertIn("path changed identity during write", text)
        self.assertIn("read-back mismatch", text)
        self.assertNotIn("args.output.parent.mkdir", text)
        self.assertNotIn("args.output.write_text", text)


if __name__ == "__main__":
    unittest.main()
