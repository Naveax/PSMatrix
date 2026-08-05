import copy
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from psmatrix.full_matrix_ga import (
    FullMatrixGAError,
    build_full_matrix_release_binding,
    canonical_full_matrix_sha256,
    canonical_full_matrix_targets,
    create_full_matrix_ga_attestation,
    load_full_matrix_release_binding,
    validate_canonical_full_matrix_report,
    verify_full_matrix_ga_attestation,
)
from psmatrix.release import create_release_manifest
from psmatrix.signing import generate_ed25519_keypair


class FullMatrixGATests(unittest.TestCase):
    def _report(self):
        rows = []
        targets = []
        for item in canonical_full_matrix_targets():
            rows.append({
                "id": item["id"], "kind": item["kind"], "runtime_id": item["runtime_id"],
                "required": item["required"], "status": "PASS",
            })
            targets.append({
                "runtime_id": item["runtime_id"],
                "runtime_version": item.get("version") or item["runtime_id"].split("-")[2],
                "source": "tool.ps1", "source_sha256": "a" * 64, "status": "PASS",
                "runtime": {"matrix_target_id": item["id"], "kind": item["kind"], "required": item["required"]},
            })
        return {
            "schema": 8, "tool_version": "2.0.0rc2", "status": "PASS",
            "started_at": datetime.now(UTC).isoformat(), "finished_at": datetime.now(UTC).isoformat(),
            "targets": targets, "differential": [], "diagnostics": [],
            "matrix": {
                "full": True, "name": "full", "differential_mode": "strict",
                "baseline_runtime": "powershell-7.6.4-linux-x64", "allowances": [],
                "allowance_manifest": None, "unallowed_differences": 0, "require_complete": True,
                "coverage": {
                    "declared": 25, "passed": 25, "incomplete": 0, "failed": 0,
                    "missing_required": [], "failed_required": [], "targets": rows,
                },
            },
        }

    def _release(self, root: Path):
        source = root / "psmatrix-2.0.0rc2-source.zip"
        wheel = root / "psmatrix-2.0.0rc2-py3-none-any.whl"
        source.write_bytes(b"source")
        wheel.write_bytes(b"wheel")
        private = root / "release-private.pem"
        public = root / "release-public.pem"
        generate_ed25519_keypair(private, public)
        manifest = root / "psmatrix-2.0.0rc2-release.json"
        old = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "0"
        try:
            create_release_manifest([source, wheel], manifest, version="2.0.0rc2", signing_private_key=private, signing_public_key=public)
        finally:
            if old is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = old
        return manifest, private, public

    def test_canonical_target_set_is_exact_and_stable(self):
        targets = canonical_full_matrix_targets()
        self.assertEqual(len(targets), 25)
        self.assertEqual(len({item["id"] for item in targets}), 25)
        self.assertEqual(len({item["runtime_id"] for item in targets}), 25)
        self.assertEqual(canonical_full_matrix_sha256(), "39eae722e73cf131ee7659371a5bc63b23481e13b1617b8f390138169bc34af2")

    def test_release_binding_and_attestation_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, release_private, release_public = self._release(root)
            binding_path = root / "binding.json"
            binding = build_full_matrix_release_binding(
                release_manifest=manifest, artifact_dir=root, release_public_key=release_public,
                release_commit="b" * 40, output=binding_path,
            )
            self.assertEqual(load_full_matrix_release_binding(binding_path), binding)
            report_path = root / "full-matrix-report.json"
            report_path.write_text(json.dumps(self._report()), encoding="utf-8")
            ci_private = root / "ci-private.pem"
            ci_public = root / "ci-public.pem"
            generate_ed25519_keypair(ci_private, ci_public)
            envelope = create_full_matrix_ga_attestation(
                report_path=report_path, release_binding_path=binding_path,
                private_key=ci_private, public_key=ci_public,
            )
            result = verify_full_matrix_ga_attestation(envelope, report_path=report_path, public_key=ci_public)
            self.assertTrue(result["valid"])
            self.assertEqual(result["targets"], 25)
            self.assertEqual(result["release_binding"]["release_commit"], "b" * 40)

    def test_fake_twenty_five_targets_are_rejected(self):
        report = self._report()
        for index, row in enumerate(report["matrix"]["coverage"]["targets"]):
            row["id"] = f"fake-{index}"
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)

    def test_duplicate_target_and_missing_optional_lane_are_rejected(self):
        report = self._report()
        report["targets"][-1]["runtime"]["matrix_target_id"] = report["targets"][0]["runtime"]["matrix_target_id"]
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)
        report = self._report()
        report["targets"] = report["targets"][:-1]
        report["matrix"]["coverage"]["targets"] = report["matrix"]["coverage"]["targets"][:-1]
        report["matrix"]["coverage"]["declared"] = 24
        report["matrix"]["coverage"]["passed"] = 24
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)

    def test_report_mode_and_allowances_are_rejected(self):
        report = self._report()
        report["matrix"]["differential_mode"] = "report"
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)
        report = self._report()
        report["matrix"]["allowances"] = [{"dimension": "execution"}]
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)

    def test_mixed_source_digest_is_rejected(self):
        report = self._report()
        report["targets"][3]["source_sha256"] = "c" * 64
        with self.assertRaises(FullMatrixGAError):
            validate_canonical_full_matrix_report(report)

    def test_tampered_release_binding_and_report_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, _, release_public = self._release(root)
            binding_path = root / "binding.json"
            build_full_matrix_release_binding(
                release_manifest=manifest, artifact_dir=root, release_public_key=release_public,
                release_commit="d" * 40, output=binding_path,
            )
            value = json.loads(binding_path.read_text())
            value["wheel"]["sha256"] = "e" * 64
            binding_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(FullMatrixGAError):
                load_full_matrix_release_binding(binding_path)

    def test_attestation_rejects_report_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, _, release_public = self._release(root)
            binding_path = root / "binding.json"
            build_full_matrix_release_binding(
                release_manifest=manifest, artifact_dir=root, release_public_key=release_public,
                release_commit="f" * 40, output=binding_path,
            )
            report_path = root / "full-matrix-report.json"
            report_path.write_text(json.dumps(self._report()), encoding="utf-8")
            private = root / "ci-private.pem"
            public = root / "ci-public.pem"
            generate_ed25519_keypair(private, public)
            envelope = create_full_matrix_ga_attestation(
                report_path=report_path, release_binding_path=binding_path, private_key=private, public_key=public,
            )
            tampered = self._report()
            tampered["targets"][0]["source_sha256"] = "9" * 64
            report_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(FullMatrixGAError):
                verify_full_matrix_ga_attestation(envelope, report_path=report_path, public_key=public)
