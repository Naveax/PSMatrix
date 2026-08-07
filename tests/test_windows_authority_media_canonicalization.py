import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "media-canonicalization-contract.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsAuthorityMediaCanonicalizationTests(unittest.TestCase):
    def test_contract_freezes_release_binding_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-media-canonicalization-contract",
        )
        self.assertTrue(value["rules"]["identical_manifest_copies_share_one_identity"])
        self.assertTrue(value["rules"]["different_manifest_identities_are_ambiguous"])
        self.assertTrue(value["rules"]["release_bound_filename_must_be_declared"])
        self.assertTrue(value["rules"]["release_bound_sha256_must_match"])
        self.assertTrue(value["rules"]["release_bound_size_must_match"])
        self.assertTrue(value["rules"]["legacy_or_cross_version_release_artifacts_are_excluded"])
        self.assertFalse(value["safety"]["downloads_files"])
        self.assertFalse(value["safety"]["extracts_archives"])
        self.assertFalse(value["safety"]["modifies_candidate_files"])
        self.assertFalse(value["safety"]["authoritative"])
        self.assertFalse(value["safety"]["ga_eligible"])

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for runtime validation")
    def test_identical_manifest_copies_collapse_and_legacy_release_files_are_excluded(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)

        with tempfile.TemporaryDirectory(prefix="psmatrix-media-canonical-") as temporary:
            root = Path(temporary)
            ga = root / "ga"
            ga.mkdir()

            manifest_value = {
                "manifest": {
                    "schema": 1,
                    "kind": "psmatrix.release-manifest",
                    "version": "2.0.0rc2",
                    "artifacts": [
                        {
                            "name": "psmatrix-2.0.0rc2-source.zip",
                            "size": 9,
                            "sha256": hashlib.sha256(b"rc2-source").hexdigest(),
                        }
                    ],
                }
            }
            manifest_text = json.dumps(manifest_value, sort_keys=True) + "\n"
            manifest_a = root / "copy-a" / "psmatrix-2.0.0rc2-release.json"
            manifest_b = root / "copy-b" / "psmatrix-2.0.0rc2-release.json"
            manifest_a.parent.mkdir()
            manifest_b.parent.mkdir()
            manifest_a.write_text(manifest_text, encoding="utf-8")
            manifest_b.write_text(manifest_text, encoding="utf-8")

            legacy_files = []
            for name, role in (
                ("psmatrix-1.6.0-source.zip", "source-archive"),
                ("psmatrix-1.6.0-windows-workers.zip", "windows-workers-package"),
                ("psmatrix-1.6.0-windows-certification-kit.zip", "windows-certification-kit"),
                ("psmatrix-1.6.0-windows-provisioning-kit.zip", "windows-provisioning-kit"),
            ):
                path = root / name
                path.write_bytes(name.encode("utf-8"))
                legacy_files.append((path, role))

            candidates = [
                {
                    "path": str(manifest_a),
                    "name": manifest_a.name,
                    "extension": ".json",
                    "size": manifest_a.stat().st_size,
                    "sha256": sha256(manifest_a),
                    "roles": ["signed-release-manifest"],
                    "classification_is_authoritative": False,
                    "iso_inventory": None,
                },
                {
                    "path": str(manifest_b),
                    "name": manifest_b.name,
                    "extension": ".json",
                    "size": manifest_b.stat().st_size,
                    "sha256": sha256(manifest_b),
                    "roles": ["signed-release-manifest"],
                    "classification_is_authoritative": False,
                    "iso_inventory": None,
                },
            ]
            for path, role in legacy_files:
                candidates.append(
                    {
                        "path": str(path),
                        "name": path.name,
                        "extension": ".zip",
                        "size": path.stat().st_size,
                        "sha256": sha256(path),
                        "roles": [role],
                        "classification_is_authoritative": False,
                        "iso_inventory": None,
                    }
                )

            inventory = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-media-inventory",
                "pack": "03-authoritative-windows",
                "status": "PASS_PARTIAL",
                "generated_at_utc": "2026-08-07T00:00:00Z",
                "source_root": str(ROOT),
                "ga_root": str(ga),
                "search_roots": [str(root)],
                "inspect_iso_images": False,
                "candidate_count": len(candidates),
                "candidates": candidates,
                "warnings": [],
                "authoritative": False,
                "ga_eligible": False,
            }
            inventory_path = ga / "windows-authority-media-inventory.json"
            output_path = ga / "windows-authority-media-inventory.canonical.json"
            inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

            result = subprocess.run(
                [
                    str(pwsh),
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(SCRIPT),
                    "-SourceRoot",
                    str(ROOT),
                    "-GaRoot",
                    str(ga),
                    "-InventoryPath",
                    str(inventory_path),
                    "-OutputPath",
                    str(output_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            report = json.loads(output_path.read_text(encoding="utf-8"))

            canonical = report["canonicalization"]
            self.assertEqual(canonical["release_authority_status"], "READY")
            self.assertEqual(canonical["release_version"], "2.0.0rc2")
            self.assertEqual(canonical["manifest_candidate_count"], 2)
            self.assertEqual(canonical["manifest_identity_count"], 1)
            self.assertEqual(len(canonical["duplicate_identical_manifest_paths"]), 1)

            self.assertEqual(report["candidate_count"], 1)
            self.assertEqual(report["candidates"][0]["roles"], ["signed-release-manifest"])
            self.assertFalse(report["release_selection_ready"])
            self.assertFalse(report["ready_for_media_manifest"])
            self.assertFalse(report["authoritative"])
            self.assertFalse(report["ga_eligible"])

            self.assertEqual(
                set(report["missing_release_roles"]),
                {
                    "source-archive",
                    "windows-workers-package",
                    "windows-certification-kit",
                    "windows-provisioning-kit",
                },
            )
            reasons = {item["reason"] for item in canonical["excluded_candidates"]}
            self.assertIn("duplicate-identical-release-manifest-copy", reasons)
            self.assertIn("artifact-not-declared-by-signed-release-manifest", reasons)


if __name__ == "__main__":
    unittest.main()
