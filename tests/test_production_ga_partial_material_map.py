from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "compose_partial_production_ga_material_map.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"

spec = importlib.util.spec_from_file_location("partial_material_map", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductionGAPartialMaterialMapTests(unittest.TestCase):
    def _contract(self):
        return json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _one_fragment(self, root: Path) -> tuple[dict, Path]:
        contract = self._contract()
        environment = contract["environments"][0]
        secret = environment["required_secrets"][0]
        material = root / "value.txt"
        material.write_text("external-material\n", encoding="utf-8")
        fragment = {
            "schema": 1,
            "kind": "psmatrix.production-ga-environment-material-map",
            "version": "2.0.0",
            "fragment": "test-one",
            "check_count": 1,
            "environments": {environment["name"]: {"secrets": {secret: str(material)}, "vars": {}}},
        }
        return fragment, material

    def test_composes_partial_map_without_readiness_claim(self):
        contract = self._contract()
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-map-") as temporary:
            fragment, _ = self._one_fragment(Path(temporary))
            value = module.compose(contract, [fragment])
            self.assertTrue(value["partial"])
            self.assertEqual(value["check_count"], 1)
            self.assertEqual(value["contract_check_count"], 41)
            self.assertFalse(value["safety"]["production_readiness_claimed"])
            self.assertFalse(value["safety"]["ga_eligible"])

    def test_duplicate_identity_across_fragments_fails_closed(self):
        contract = self._contract()
        environment = contract["environments"][0]
        secret = environment["required_secrets"][0]
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-map-") as temporary:
            material = Path(temporary) / "value.txt"
            material.write_text("external-material\n", encoding="utf-8")
            base = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "check_count": 1, "environments": {environment["name"]: {"secrets": {secret: str(material)}, "vars": {}}}}
            first = dict(base, fragment="one")
            second = dict(base, fragment="two")
            with self.assertRaises(module.PartialMaterialMapError):
                module.compose(contract, [first, second])

    def test_full_forty_one_check_input_is_not_mislabelled_partial(self):
        contract = self._contract()
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-map-") as temporary:
            root = Path(temporary)
            environments = {}
            count = 0
            for row in contract["environments"]:
                secrets = {}
                variables = {}
                for source, names, target in (("secret", row["required_secrets"], secrets), ("var", row["required_vars"], variables)):
                    for name in names:
                        path = root / f"{count}-{source}.txt"
                        path.write_text("x\n", encoding="utf-8")
                        target[name] = str(path)
                        count += 1
                environments[row["name"]] = {"secrets": secrets, "vars": variables}
            fragment = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "fragment": "full", "check_count": count, "environments": environments}
            self.assertEqual(count, 41)
            with self.assertRaises(module.PartialMaterialMapError):
                module.compose(contract, [fragment])

    def test_hardlinked_material_file_is_rejected_when_supported(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-map-hardlink-") as temporary:
            root = Path(temporary)
            fragment, material = self._one_fragment(root)
            alias = root / "material-alias.txt"
            try:
                os.link(material, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(module.PartialMaterialMapError, "must not be hardlinked"):
                module.compose(self._contract(), [fragment])

    def test_hardlinked_fragment_input_is_rejected_when_supported(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-fragment-hardlink-") as temporary:
            root = Path(temporary)
            source = root / "fragment.json"
            alias = root / "fragment-alias.json"
            source.write_text("{}\n", encoding="utf-8")
            try:
                os.link(source, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(module.PartialMaterialMapError, "must not be hardlinked"):
                module._safe_regular_file(source, "material-map fragment input")

    def test_repo_local_nested_output_is_rejected_before_directory_creation(self):
        forbidden = ROOT / ".tmp-partial-map-output" / "nested" / "map.json"
        try:
            with self.assertRaisesRegex(module.PartialMaterialMapError, "must stay outside repository"):
                module._safe_external_output(forbidden)
            self.assertFalse((ROOT / ".tmp-partial-map-output").exists())
        finally:
            parent = ROOT / ".tmp-partial-map-output"
            if parent.exists():
                shutil.rmtree(parent)

    def test_hardlinked_output_is_rejected_without_target_mutation(self):
        with tempfile.TemporaryDirectory(prefix="psmatrix-partial-output-hardlink-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            output = root / "output.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(module.PartialMaterialMapError, "must not be hardlinked"):
                module._safe_external_output(output)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_uses_lstat_hardlink_checks_and_atomic_output(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(output, value)", source)


if __name__ == "__main__":
    unittest.main()
