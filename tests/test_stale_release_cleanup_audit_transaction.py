from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "cleanup_stale_release_work.py"


def load_module():
    spec = importlib.util.spec_from_file_location("stale_cleanup_audit_transaction", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_closure() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.release-closure-readiness",
        "version": "2.0.0",
        "status": "READY_FOR_RELEASE_CLOSURE",
        "execution_head": "a" * 40,
        "ga_eligible": True,
        "release_closed": False,
    }


def immutable_release() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "psmatrix.final-immutable-release-verification",
        "version": "2.0.0",
        "status": "PASS",
        "repository": "Naveax/PSMatrix",
        "tag": "v2.0.0",
        "release_execution_control_head": "a" * 40,
        "publication_operation_verified": True,
        "publication_asset_count": 9,
        "release_asset_set_verified": True,
        "github_release_attestation_verified": True,
        "release_published": True,
        "final_immutable_ga_anchor_created": True,
        "release_closed": False,
    }


class StaleReleaseCleanupAuditTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.verifier = self.module._load_verifier()
        self.closure = release_closure()
        self.immutable = immutable_release()

    def test_reservation_is_exclusive_and_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "operation.json"
            output.write_text("preserve\n", encoding="utf-8")
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._reserve_output(output, "cleanup operation output")
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve\n")

    def test_missing_parent_fails_before_any_reservation_file_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "missing" / "operation.json"
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._reserve_output(output, "cleanup operation output")
            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_finalize_reserved_output_writes_exact_json_and_preserves_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "operation.json"
            reservation = self.module._reserve_output(output, "cleanup operation output")
            value = {"schema": 1, "status": "PASS"}
            self.module._finalize_reserved_output(reservation, value)
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_second_finalize_failure_removes_both_reserved_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation = root / "operation.json"
            verification = root / "verification.json"
            first = self.module._reserve_output(operation, "cleanup operation output")
            second = self.module._reserve_output(
                verification, "cleanup verification output"
            )
            original = self.module._finalize_reserved_output
            calls = 0

            def flaky_finalize(reservation, value):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise self.module.StaleReleaseWorkCleanupOperationError(
                        "forced second finalize failure"
                    )
                return original(reservation, value)

            with (
                patch.object(
                    self.module,
                    "_finalize_reserved_output",
                    side_effect=flaky_finalize,
                ),
                self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
            ):
                self.module._finalize_reserved_outputs(
                    [
                        (first, {"status": "PASS", "which": "operation"}),
                        (second, {"status": "PASS", "which": "verification"}),
                    ]
                )

            self.assertFalse(operation.exists())
            self.assertFalse(verification.exists())

    def test_second_execute_reservation_failure_cleans_first_before_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = root / "closure.json"
            immutable = root / "immutable.json"
            closure.write_text("{}\n", encoding="utf-8")
            immutable.write_text("{}\n", encoding="utf-8")
            operation = root / "operation.json"
            verification = root / "verification.json"
            verification.write_text("preserve\n", encoding="utf-8")
            argv = [
                str(SCRIPT),
                "--release-closure",
                str(closure),
                "--immutable-release-verification",
                str(immutable),
                "--repository",
                "Naveax/PSMatrix",
                "--gh",
                "gh",
                "--execute",
                "--output",
                str(operation),
                "--verification-output",
                str(verification),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    self.module,
                    "run_operation",
                    side_effect=AssertionError("reservation failure reached operation"),
                ),
                patch.object(sys, "stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(self.module.main(), 1)

            self.assertFalse(operation.exists())
            self.assertEqual(verification.read_text(encoding="utf-8"), "preserve\n")

    def test_audit_finalize_failure_rolls_back_deleted_refs(self) -> None:
        branches = [{"name": "main"}, {"name": "prod/old-one"}]
        plan = self.module.build_plan(
            self.verifier,
            self.closure,
            self.immutable,
            branches,
            [],
            [{"branch": "prod/old-one", "sha": "b" * 40}],
        )
        restored: list[tuple[str, str]] = []

        with (
            patch.object(
                self.module,
                "_branch_ref",
                return_value={"branch": "prod/old-one", "sha": "b" * 40},
            ),
            patch.object(self.module, "_gh_delete", return_value=None),
            patch.object(
                self.module,
                "_paged_list",
                side_effect=lambda _gh, endpoint: [] if "pulls?state=open" in endpoint else [{"name": "main"}],
            ),
            patch.object(
                self.module,
                "_gh_create_ref",
                side_effect=lambda _gh, _repo, branch, sha: restored.append((branch, sha)),
            ),
            self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError),
        ):
            self.module.execute_plan(
                self.verifier,
                plan,
                self.closure,
                self.immutable,
                "Naveax/PSMatrix",
                "gh",
                audit_finalizer=lambda _receipt, _verification: (_ for _ in ()).throw(
                    self.module.StaleReleaseWorkCleanupOperationError("forced audit finalization failure")
                ),
            )

        self.assertEqual(restored, [("prod/old-one", "b" * 40)])

    def test_source_requires_reservation_before_execute_run_operation(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("audit_finalizer", text)
        main = text[text.index("def main()") :]
        reserve = main.index("_reserve_output(")
        execute = main.index("run_operation(")
        self.assertLess(reserve, execute)
        self.assertNotIn("args.output.parent.mkdir", main)
        self.assertNotIn("args.output.write_text", main)


if __name__ == "__main__":
    unittest.main()
