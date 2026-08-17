from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
PROVISION = ROOT / "scripts" / "ga" / "provision_production_ga_authorities.py"
SCRIPT = ROOT / "scripts" / "ga" / "build_authority_material_map_fragment.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AuthorityMaterialMapFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.provision = load(PROVISION, "provision_authorities_for_fragment")
        cls.fragment = load(SCRIPT, "authority_material_map_fragment")

    def test_generated_authorities_map_exact_nine_environments_and_seventeen_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-") as temporary:
            authority_root = Path(temporary) / "authorities"
            self.provision.provision_authorities(authority_root)
            value = self.fragment.build_fragment(authority_root)
            self.assertEqual(value["environment_count"], 9)
            self.assertEqual(value["check_count"], 17)
            self.assertEqual(len(value["environments"]), 9)
            release = value["environments"]["production-ga-release-signing"]
            self.assertEqual(set(release["secrets"]), {"PSMATRIX_RELEASE_PRIVATE_KEY"})
            self.assertEqual(release["vars"], {})
            self.assertFalse(value["safety"]["values_serialized"])

    def test_all_paths_are_external_files_and_map_contains_no_pem_material(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-") as temporary:
            authority_root = Path(temporary) / "authorities"
            self.provision.provision_authorities(authority_root)
            value = self.fragment.build_fragment(authority_root)
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn("BEGIN PRIVATE KEY", serialized)
            self.assertNotIn("BEGIN PUBLIC KEY", serialized)
            for environment in value["environments"].values():
                for path in environment["secrets"].values():
                    resolved = Path(path)
                    self.assertTrue(resolved.is_file())
                    with self.assertRaises(ValueError):
                        resolved.resolve().relative_to(ROOT.resolve())

    def test_missing_authority_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-") as temporary:
            authority_root = Path(temporary) / "authorities"
            self.provision.provision_authorities(authority_root)
            (authority_root / "ci.private.pem").unlink()
            with self.assertRaises(self.fragment.AuthorityFragmentError):
                self.fragment.build_fragment(authority_root)

    def test_manifest_cannot_redirect_authority_file_outside_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-escape-") as temporary:
            root = Path(temporary)
            authority_root = root / "authorities"
            self.provision.provision_authorities(authority_root)
            outside = root / "outside.private.pem"
            outside.write_text("sentinel\n", encoding="utf-8")
            manifest_path = authority_root / "production-ga-authorities.manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            release = next(row for row in manifest["authorities"] if row["role"] == "release")
            release["private_file"] = "../outside.private.pem"
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(self.fragment.AuthorityFragmentError, "authority file identity mismatch"):
                self.fragment.build_fragment(authority_root)
            self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel\n")

    def test_absolute_manifest_authority_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-absolute-") as temporary:
            root = Path(temporary)
            authority_root = root / "authorities"
            self.provision.provision_authorities(authority_root)
            outside = root / "outside.public.pem"
            outside.write_text("sentinel\n", encoding="utf-8")
            manifest_path = authority_root / "production-ga-authorities.manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            release = next(row for row in manifest["authorities"] if row["role"] == "release")
            release["public_file"] = str(outside)
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(self.fragment.AuthorityFragmentError, "authority file identity mismatch"):
                self.fragment.build_fragment(authority_root)

    def test_hardlinked_authority_file_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-hardlink-") as temporary:
            root = Path(temporary)
            authority_root = root / "authorities"
            self.provision.provision_authorities(authority_root)
            private_path = authority_root / "release.private.pem"
            target = root / "release-private-target.pem"
            try:
                target.write_bytes(private_path.read_bytes())
                private_path.unlink()
                os.link(target, private_path)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.fragment.AuthorityFragmentError, "must not be hardlinked"):
                self.fragment.build_fragment(authority_root)

    def test_hardlinked_manifest_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-manifest-hardlink-") as temporary:
            root = Path(temporary)
            authority_root = root / "authorities"
            self.provision.provision_authorities(authority_root)
            manifest = authority_root / "production-ga-authorities.manifest.json"
            alias_target = root / "manifest-target.json"
            try:
                alias_target.write_bytes(manifest.read_bytes())
                manifest.unlink()
                os.link(alias_target, manifest)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.fragment.AuthorityFragmentError, "must not be hardlinked"):
                self.fragment.build_fragment(authority_root)

    def test_hardlinked_fragment_output_is_rejected_without_target_mutation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-authority-fragment-output-hardlink-") as temporary:
            root = Path(temporary)
            authority_root = root / "authorities"
            self.provision.provision_authorities(authority_root)
            value = self.fragment.build_fragment(authority_root)
            target = root / "target.json"
            output = root / "fragment.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.fragment.AuthorityFragmentError, "must not be hardlinked"):
                self.fragment.write_fragment(output, value)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_freezes_direct_child_and_atomic_output_contract(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('expected_private_name = f"{role}.private.pem"', source)
        self.assertIn('expected_public_name = f"{role}.public.pem"', source)
        self.assertIn("private_name != expected_private_name", source)
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(target, value)", source)


if __name__ == "__main__":
    unittest.main()
