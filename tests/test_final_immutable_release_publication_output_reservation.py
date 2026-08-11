from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "publish_final_immutable_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("publisher_output_reservation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalImmutableReleasePublicationOutputReservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def roots(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary)
        bundle = root / "bundle"
        receipts = root / "receipts"
        bundle.mkdir()
        receipts.mkdir()
        return bundle, receipts

    def test_reservation_writes_fsynced_pending_then_final_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, receipts = self.roots(temporary)
            output = receipts / "publication.json"
            handle, path, identity = self.module._reserve_publication_output(output, bundle)
            try:
                pending = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(pending["status"], "PENDING")
                self.assertEqual(
                    pending["kind"],
                    "psmatrix.final-immutable-release-publication-output-reservation",
                )
                self.assertFalse(pending["mutation_executed"])
                final = {
                    "schema": 1,
                    "kind": "psmatrix.final-immutable-release-publication-operation",
                    "version": "2.0.0",
                    "status": "PASS",
                    "release_closed": False,
                }
                self.module._write_reserved_receipt(handle, path, identity, final)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), final)
            finally:
                handle.close()

    def test_existing_output_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, receipts = self.roots(temporary)
            output = receipts / "publication.json"
            output.write_text("KEEP\n", encoding="utf-8")
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(output, bundle)
            self.assertEqual(output.read_text(encoding="utf-8"), "KEEP\n")

    def test_output_inside_repository_is_rejected_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, _receipts = self.roots(temporary)
            output = ROOT / ".publisher-output-reservation-never-create.json"
            self.assertFalse(output.exists())
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(output, bundle)
            self.assertFalse(output.exists())

    def test_output_inside_protected_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, _receipts = self.roots(temporary)
            output = bundle / "publication.json"
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(output, bundle)
            self.assertFalse(output.exists())

    def test_missing_output_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, receipts = self.roots(temporary)
            output = receipts / "missing" / "publication.json"
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(output, bundle)
            self.assertFalse(output.exists())

    def test_output_leaf_and_parent_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, receipts = self.roots(temporary)
            real = receipts / "real"
            real.mkdir()
            target = real / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            leaf = receipts / "leaf.json"
            parent = receipts / "parent-link"
            try:
                leaf.symlink_to(target)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(leaf, bundle)
            with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                self.module._reserve_publication_output(parent / "new.json", bundle)

    def test_path_replacement_while_descriptor_open_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, receipts = self.roots(temporary)
            output = receipts / "publication.json"
            handle, path, identity = self.module._reserve_publication_output(output, bundle)
            try:
                try:
                    path.unlink()
                    path.write_text("replacement\n", encoding="utf-8")
                except (OSError, PermissionError):
                    self.skipTest("platform does not permit replacing an open file path")
                with self.assertRaises(self.module.FinalImmutableReleasePublicationError):
                    self.module._write_reserved_receipt(
                        handle,
                        path,
                        identity,
                        {"status": "PASS"},
                    )
            finally:
                handle.close()

    def test_main_reserves_output_before_execute_plan(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main_start = text.index("def main")
        self.assertLess(
            text.index("_reserve_publication_output(", main_start),
            text.index("execute_plan(", main_start),
        )
        self.assertIn("publication_receipt_output_reserved_before_mutation=true", text)
        self.assertNotIn("args.output.write_text", text)


if __name__ == "__main__":
    unittest.main()
