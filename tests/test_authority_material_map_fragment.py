from __future__ import annotations

import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
