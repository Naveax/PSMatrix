from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "merge_production_ga_material_map_fragments.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"


def load():
    spec = importlib.util.spec_from_file_location("material_map_merger", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGAMaterialMapMergerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def _fragments(self, root: Path) -> list[dict]:
        groups = {
            name: {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "fragment": name, "check_count": 0, "environments": {}}
            for name in ("signing-authorities", "full-matrix-local-paths", "public-auth", "external-otlp", "independent-security-review")
        }
        signing_envs = {"production-ga-release-signing", "production-ga-windows-lab", "production-ga-ci-signing", "production-ga-deployment-signing", "production-ga-operations-signing", "production-ga-recovery-signing", "production-ga-vulnerability-scanner-signing", "production-ga-root-signing"}
        for row in self.contract["environments"]:
            environment = row["name"]
            for source_key, map_key in (("required_secrets", "secrets"), ("required_vars", "vars")):
                for name in row[source_key]:
                    if environment == "production-ga-full-matrix":
                        group = "full-matrix-local-paths"
                    elif environment == "production-ga-public-auth-probe":
                        group = "public-auth"
                    elif environment == "production-ga-external-otlp-probe":
                        group = "external-otlp"
                    elif environment == "production-ga-security-review-signing" and map_key == "vars":
                        group = "independent-security-review"
                    elif environment in signing_envs or environment == "production-ga-security-review-signing":
                        group = "signing-authorities"
                    else:
                        raise AssertionError((environment, map_key, name))
                    target = groups[group]["environments"].setdefault(environment, {"secrets": {}, "vars": {}})
                    path = root / group / environment / f"{name}.txt"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"fixture-{group}-{name}\n", encoding="utf-8")
                    target[map_key][name] = str(path)
                    groups[group]["check_count"] += 1
        self.assertEqual([groups[name]["check_count"] for name in groups], [17, 2, 19, 2, 1])
        return list(groups.values())

    def test_five_fragments_close_exact_twelve_environment_forty_one_check_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-material-map-merge-") as temporary:
            value = self.module.merge_fragments(self.contract, self._fragments(Path(temporary)))
            self.assertEqual(value["fragment_count"], 5)
            self.assertEqual(value["environment_count"], 12)
            self.assertEqual(value["check_count"], 41)
            self.assertEqual(sum(len(entry["secrets"]) + len(entry["vars"]) for entry in value["environments"].values()), 41)
            self.assertTrue(value["safety"]["all_material_files_external"])
            self.assertFalse(value["safety"]["inline_values_present"])

    def test_missing_fragment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-material-map-merge-") as temporary:
            with self.assertRaises(self.module.MaterialMapMergeError):
                self.module.merge_fragments(self.contract, self._fragments(Path(temporary))[:-1])

    def test_duplicate_identity_across_fragments_fails_even_when_path_matches(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-material-map-merge-") as temporary:
            fragments = self._fragments(Path(temporary))
            first = fragments[0]
            environment = next(iter(first["environments"]))
            source = "secrets" if first["environments"][environment]["secrets"] else "vars"
            name, path = next(iter(first["environments"][environment][source].items()))
            duplicate = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "fragment": "duplicate", "check_count": 1, "environments": {environment: {"secrets": {}, "vars": {}}}}
            duplicate["environments"][environment][source][name] = path
            with self.assertRaises(self.module.MaterialMapMergeError):
                self.module.merge_fragments(self.contract, [*fragments, duplicate])

    def test_undeclared_name_and_repo_local_material_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-material-map-merge-") as temporary:
            fragments = self._fragments(Path(temporary))
            fragments[0]["environments"]["production-ga-release-signing"]["secrets"]["UNDECLARED"] = "C:/nowhere"
            fragments[0]["check_count"] += 1
            with self.assertRaises(self.module.MaterialMapMergeError):
                self.module.merge_fragments(self.contract, fragments)
        inside = ROOT / ".tmp-material-value.txt"
        try:
            inside.write_text("fixture", encoding="utf-8")
            fragment = {"schema": 1, "kind": "psmatrix.production-ga-environment-material-map", "version": "2.0.0", "fragment": "bad", "check_count": 1, "environments": {"production-ga-release-signing": {"secrets": {"PSMATRIX_RELEASE_PRIVATE_KEY": str(inside)}, "vars": {}}}}
            with self.assertRaises(self.module.MaterialMapMergeError):
                self.module.merge_fragments(self.contract, [fragment])
        finally:
            inside.unlink(missing_ok=True)

    def test_hardlinked_material_file_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-material-map-hardlink-") as temporary:
            root = Path(temporary)
            fragments = self._fragments(root)
            first = fragments[0]
            environment = next(iter(first["environments"]))
            source = "secrets" if first["environments"][environment]["secrets"] else "vars"
            _, raw_path = next(iter(first["environments"][environment][source].items()))
            material = Path(raw_path)
            alias = root / "material-alias.txt"
            try:
                os.link(material, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.MaterialMapMergeError, "must not be hardlinked"):
                self.module.merge_fragments(self.contract, fragments)

    def test_hardlinked_fragment_input_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-merge-fragment-hardlink-") as temporary:
            root = Path(temporary)
            source = root / "fragment.json"
            alias = root / "fragment-alias.json"
            source.write_text("{}\n", encoding="utf-8")
            try:
                os.link(source, alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.MaterialMapMergeError, "must not be hardlinked"):
                self.module._safe_regular_file(source, "material-map fragment input")

    def test_repo_local_nested_output_is_rejected_before_directory_creation(self) -> None:
        forbidden_root = ROOT / ".tmp-merged-map-output"
        try:
            with self.assertRaisesRegex(self.module.MaterialMapMergeError, "must stay outside repository"):
                self.module._safe_external_output(forbidden_root / "nested" / "map.json")
            self.assertFalse(forbidden_root.exists())
        finally:
            if forbidden_root.exists():
                shutil.rmtree(forbidden_root)

    def test_hardlinked_output_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-merge-output-hardlink-") as temporary:
            root = Path(temporary)
            target = root / "target.json"
            output = root / "output.json"
            target.write_text("sentinel\n", encoding="utf-8")
            try:
                os.link(target, output)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(self.module.MaterialMapMergeError, "must not be hardlinked"):
                self.module._safe_external_output(output)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_source_uses_lstat_hardlink_checks_and_atomic_output(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(".lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(output, value)", source)


if __name__ == "__main__":
    unittest.main()
