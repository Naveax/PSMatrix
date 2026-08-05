import unittest

from psmatrix.catalog import matrix_versions, resolve_runtime, version_key


class CatalogTests(unittest.TestCase):
    def test_exact_runtime_asset(self):
        spec = resolve_runtime("7.6.4", "x64")
        self.assertEqual(spec.artifact_name, "powershell-7.6.4-linux-x64.tar.gz")
        self.assertIn("/v7.6.4/", spec.download_url)

    def test_channel_resolution(self):
        spec = resolve_runtime("stable", "x64")
        self.assertEqual(spec.version, "7.6.4")
        self.assertEqual(spec.channel, "stable")

    def test_default_matrix_has_unique_versions(self):
        values = matrix_versions("default")
        self.assertEqual(values, list(dict.fromkeys(values)))


class HistoricalMatrixTests(unittest.TestCase):
    def test_core_all_covers_60_through_76(self):
        values = matrix_versions("core-all")
        self.assertEqual(values[0], "6.0.5")
        self.assertEqual(values[-1], "7.6.4")
        self.assertEqual(len(values), 10)

    def test_musl_artifact_and_runtime_id_are_distinct(self):
        spec = resolve_runtime("7.6.4", "x64", "musl")
        self.assertEqual(spec.artifact_name, "powershell-7.6.4-linux-musl-x64.tar.gz")
        self.assertTrue(spec.runtime_id.endswith("-musl"))

    def test_semantic_version_order(self):
        values = ["7.7.0-preview.2", "7.6.4", "6.2.7"]
        self.assertEqual(sorted(values, key=version_key), ["6.2.7", "7.6.4", "7.7.0-preview.2"])
