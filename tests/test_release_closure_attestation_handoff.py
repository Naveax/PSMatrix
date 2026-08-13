from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_release_closure_from_attestation_operation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("release_closure_attestation_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseClosureAttestationHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.head = "a" * 40
        self.verification_path = self.root / "final-attestation-verification.json"
        self.verification = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "execution_control_head": self.head,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.verification_path.write_text(json.dumps(self.verification) + "\n", encoding="utf-8")
        digest = hashlib.sha256(self.verification_path.read_bytes()).hexdigest()
        self.operation_path = self.root / "operation.json"
        self.operation = {
            "schema": 1,
            "kind": "psmatrix.final-ga-attestation-content-operation",
            "version": "2.0.0",
            "status": "PASS",
            "execution_head": self.head,
            "verification_receipt": str(self.verification_path),
            "verification_receipt_sha256": digest,
            "exact_api_artifact_id_used": True,
            "safe_extraction_verified": True,
            "semantic_verifier_repository_owned": True,
            "semantic_verification_mutated_tree": False,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
        }
        self.operation_path.write_text(json.dumps(self.operation) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _symlink_or_skip(
        self,
        link: Path,
        target: Path,
        *,
        target_is_directory: bool = False,
    ) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable on this runner: {exc}")

    def test_exact_attestation_operation_resolves_bound_verification(self) -> None:
        value, path = self.module.resolve_attestation_verification(self.operation, self.operation_path)
        self.assertEqual(value["execution_control_head"], self.head)
        self.assertEqual(path, self.verification_path.resolve())

    def test_verification_digest_tamper_fails_closed(self) -> None:
        self.operation["verification_receipt_sha256"] = "0" * 64
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_execution_head_drift_fails_closed(self) -> None:
        self.verification["execution_control_head"] = "b" * 40
        self.verification_path.write_text(json.dumps(self.verification) + "\n", encoding="utf-8")
        self.operation["verification_receipt_sha256"] = hashlib.sha256(self.verification_path.read_bytes()).hexdigest()
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_tree_mutation_flag_fails_closed(self) -> None:
        self.operation["semantic_verification_mutated_tree"] = True
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(self.operation, self.operation_path)

    def test_verification_receipt_parent_symlink_traversal_fails_closed(self) -> None:
        real_parent = self.root / "real-receipts"
        real_parent.mkdir()
        real_verification = real_parent / "verification.json"
        real_verification.write_text(
            json.dumps(self.verification) + "\n",
            encoding="utf-8",
        )
        link_parent = self.root / "linked-receipts"
        self._symlink_or_skip(
            link_parent,
            real_parent,
            target_is_directory=True,
        )
        self.operation["verification_receipt"] = str(
            link_parent / real_verification.name
        )
        self.operation["verification_receipt_sha256"] = hashlib.sha256(
            real_verification.read_bytes()
        ).hexdigest()

        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module.resolve_attestation_verification(
                self.operation,
                self.operation_path,
            )

    def test_handoff_output_is_write_once_and_exact(self) -> None:
        output = self.root / "release-closure-handoff.json"
        value = {
            "schema": 1,
            "status": "READY_FOR_RELEASE_CLOSURE",
            "release_closed": False,
        }
        expected = json.dumps(value, indent=2, sort_keys=True) + "\n"

        written = self.module._write_release_closure_handoff_receipt(
            output,
            value,
        )

        self.assertEqual(written, output.resolve())
        self.assertEqual(output.read_text(encoding="utf-8"), expected)
        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module._write_release_closure_handoff_receipt(
                output,
                {"status": "FORGED"},
            )
        self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_handoff_output_parent_symlink_traversal_fails_closed(self) -> None:
        real_parent = self.root / "real-output"
        real_parent.mkdir()
        link_parent = self.root / "linked-output"
        self._symlink_or_skip(
            link_parent,
            real_parent,
            target_is_directory=True,
        )

        with self.assertRaises(self.module.ReleaseClosureAttestationHandoffError):
            self.module._write_release_closure_handoff_receipt(
                link_parent / "handoff.json",
                {"status": "READY_FOR_RELEASE_CLOSURE"},
            )
        self.assertFalse((real_parent / "handoff.json").exists())

    def test_handoff_output_readback_mismatch_fails_closed_and_unlinks_created_file(self) -> None:
        output = self.root / "readback-mismatch.json"
        original_fdopen = self.module.os.fdopen

        class CorruptingReadbackHandle:
            def __init__(self, handle):
                self._handle = handle

            def write(self, value):
                return self._handle.write(value)

            def flush(self):
                return self._handle.flush()

            def fileno(self):
                return self._handle.fileno()

            def seek(self, *args):
                return self._handle.seek(*args)

            def read(self, *args):
                return self._handle.read(*args) + "corrupted-readback"

            def close(self):
                return self._handle.close()

        def corrupting_fdopen(fd, *args, **kwargs):
            return CorruptingReadbackHandle(
                original_fdopen(fd, *args, **kwargs)
            )

        with patch.object(
            self.module.os,
            "fdopen",
            side_effect=corrupting_fdopen,
        ):
            with self.assertRaises(
                self.module.ReleaseClosureAttestationHandoffError
            ):
                self.module._write_release_closure_handoff_receipt(
                    output,
                    {"status": "READY_FOR_RELEASE_CLOSURE"},
                )

        self.assertFalse(output.exists())

    def test_source_delegates_to_existing_five_precondition_builder(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_release_closure_readiness.py", text)
        self.assertIn("builder.build", text)
        self.assertIn("verification_receipt_sha256", text)
        self.assertIn("_reject_symlink_components", text)
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("release closure attestation handoff output read-back verification failed", text)
        self.assertIn("READY_FOR_RELEASE_CLOSURE", text)
        self.assertIn("release_closed=false", text)


if __name__ == "__main__":
    unittest.main()
